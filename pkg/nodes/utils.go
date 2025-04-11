package nodes

import (
	"time"

	"gorm.io/gorm"
)

// For testing - allows us to mock time.Now()
var timeNow = time.Now

// IsActive determines if a node is active based on when it was last seen.
// The inactive parameter specifies the number of hours a node can be without
// checking in before it's considered inactive.
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
// (active, inactive, all) to the provided gorm query
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

	// Get active count
	cutoff := ActiveTimeCutoff(hours)
	if err := baseQuery.Where("last_seen > ?", cutoff).Count(&stats.Active).Error; err != nil {
		return stats, err
	}

	// Get inactive count
	// Calculate inactive count as total - active to be consistent
	stats.Inactive = stats.Total - stats.Active

	return stats, nil
}
