package nodes

import (
	"time"

	"gorm.io/gorm"
)

// For testing - allows us to mock time.Now()
var timeNow = time.Now

// IsActive determines if a node is active based on when it was last seen.
// The inactive parameter specifies the number of hours a node can be without
// checking in before it's considered inactive. This number is expected positive.
// Returns true if the node has checked in within the specified timeframe.
func IsActive(n OsqueryNode, inactive int64) bool {
	// If LastSeen is zero (never seen), node is not active
	if n.LastSeen.IsZero() {
		return false
	}
	// A node is active if it was seen more recently than the inactive threshold
	cutoffTime := ActiveTimeCutoff(inactive)
	return n.LastSeen.After(cutoffTime)
}

// ActiveTimeCutoff returns the cutoff time for active nodes
// based on the specified number of hours
func ActiveTimeCutoff(hours int64) time.Time {
	return timeNow().Add(-time.Duration(hours) * time.Hour)
}

// ApplyNodeTarget adds the appropriate query constraints for the target node status
// (active, inactive, all) to the provided gorm query. Default is all nodes.
func ApplyNodeTarget(query *gorm.DB, target string, hours int64) *gorm.DB {
	switch target {
	case AllNodes:
		return query
	case ActiveNodes:
		cutoff := ActiveTimeCutoff(hours)
		return query.Where("last_seen > ?", cutoff)
	case InactiveNodes:
		cutoff := ActiveTimeCutoff(hours)
		return query.Where("last_seen <= ?", cutoff)
	default:
		return query
	}
}

// GetStats retrieves node statistics (total, active, inactive) for the given filter condition
func GetStats(db *gorm.DB, column, value string, hours int64) (StatsData, error) {
	var stats StatsData

	// Base query with the filter condition
	baseQuery := db.Model(&OsqueryNode{}).Where(column+" = ?", value)

	// Get total count
	if err := baseQuery.Count(&stats.Total).Error; err != nil {
		return stats, err
	}

	// Get active count - nodes seen after the cutoff time
	cutoff := ActiveTimeCutoff(hours)
	activeQuery := db.Model(&OsqueryNode{}).Where(column+" = ?", value).Where("last_seen > ?", cutoff)
	if err := activeQuery.Count(&stats.Active).Error; err != nil {
		return stats, err
	}

	// Get inactive count
	// Calculate inactive count as total - active to be consistent
	stats.Inactive = stats.Total - stats.Active

	return stats, nil
}

// PlatformCounts buckets nodes by `platform` value. Three families are
// normalized into the canonical osquery-side names; everything else lands in
// Other. The buckets mirror what the SPA's Nodes-table QuickFilters chip row
// shows ([Linux] [Windows] [macOS] [Other]).
type PlatformCounts struct {
	Linux   int64 `json:"linux"`
	Darwin  int64 `json:"darwin"`
	Windows int64 `json:"windows"`
	Other   int64 `json:"other"`
}

// OsqueryVersionCount is one row of the osquery-versions breakdown. Used by
// the dashboard's "agent fleet hygiene" panel to spot stale agents.
type OsqueryVersionCount struct {
	Version string `json:"version"`
	Count   int64  `json:"count"`
}

// GetOsqueryVersionCounts returns the per-version node counts across every
// environment the caller's already filtered down to (no env arg — the dashboard
// renders fleet-wide; if a per-env variant is wanted later it lives next to
// this one). Sorted by count DESC so the most-common version sits first.
// One GROUP BY query.
func GetOsqueryVersionCounts(db *gorm.DB) ([]OsqueryVersionCount, error) {
	var rows []OsqueryVersionCount
	err := db.Model(&OsqueryNode{}).
		Select("osquery_version AS version, COUNT(*) AS count").
		Where("osquery_version <> ''").
		Group("osquery_version").
		Order("count DESC").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// GetPlatformCountsByEnv returns the per-platform node counts for one env.
// One GROUP BY `platform` query, then we bucket the rows in Go because
// osquery agents report `kali`, `ubuntu`, `centos`, etc. — all of which
// collapse into the `linux` bucket. Doing the mapping client-side keeps the
// SQL portable and easy to extend.
//
// Counts include both active and inactive nodes — that's the right shape for
// a "this env runs 12 Linux boxes" filter chip; "how many of those are active
// right now" lives on StatsData and is rendered separately.
func GetPlatformCountsByEnv(db *gorm.DB, environment string) (PlatformCounts, error) {
	var rows []struct {
		Platform string
		N        int64
	}
	err := db.Model(&OsqueryNode{}).
		Select("platform, COUNT(*) AS n").
		Where("environment = ?", environment).
		Group("platform").
		Scan(&rows).Error
	var out PlatformCounts
	if err != nil {
		return out, err
	}
	for _, r := range rows {
		switch normalizePlatformBucket(r.Platform) {
		case "linux":
			out.Linux += r.N
		case "darwin":
			out.Darwin += r.N
		case "windows":
			out.Windows += r.N
		default:
			out.Other += r.N
		}
	}
	return out, nil
}

// platformsByBucket is the inverse of normalizePlatformBucket — given a
// canonical bucket name, return the literal `platform` column values that
// belong in it. Used by applyPlatformBucket to add an `IN (...)` filter.
// Kept in sync with normalizePlatformBucket; the two functions share the
// list of recognised distros so a change here without one there would
// silently mis-bucket nodes.
var platformsByBucket = map[string][]string{
	"linux": {
		"linux", "kali", "ubuntu", "debian", "centos", "rhel", "fedora",
		"arch", "amzn", "amazon", "opensuse", "sles", "alpine", "rocky",
		"oracle", "almalinux",
	},
	"darwin":  {"darwin", "macos", "mac"},
	"windows": {"windows", "win", "win32", "win64"},
}

// applyPlatformBucket narrows a node query to one of the four buckets.
// Empty / unknown bucket → no filter (passthrough).
// "other" is the negation of (linux ∪ darwin ∪ windows): every platform that
// doesn't appear in any known list. Implemented as `platform NOT IN (...)`.
func applyPlatformBucket(q *gorm.DB, bucket string) *gorm.DB {
	if bucket == "" {
		return q
	}
	if vals, ok := platformsByBucket[bucket]; ok {
		return q.Where("platform IN ?", vals)
	}
	if bucket == "other" {
		// Everything not in any recognised bucket.
		all := make([]string, 0, 32)
		for _, vals := range platformsByBucket {
			all = append(all, vals...)
		}
		return q.Where("platform NOT IN ?", all)
	}
	// Unknown bucket — caller can pass user input safely; no filter applied.
	return q
}

// normalizePlatformBucket folds the osquery-reported platform string into the
// SPA-facing buckets. Reads from platformsByBucket so we only maintain one
// list of recognised distros. Anything not in any bucket lands in "other".
func normalizePlatformBucket(p string) string {
	for bucket, vals := range platformsByBucket {
		for _, v := range vals {
			if v == p {
				return bucket
			}
		}
	}
	return "other"
}
