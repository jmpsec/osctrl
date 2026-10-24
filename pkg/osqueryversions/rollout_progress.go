package osqueryversions

import (
	"sort"
	"time"
	"unicode"
)

const (
	maxRolledBackHosts = 50
	maxReasonLen       = 256
)

// RolloutCounts are the host counts of a rollout.
type RolloutCounts struct{ Eligible, Upgraded, Waiting, RolledBack int }

// RolledBackHost is a host that rejected the rollout's version.
type RolledBackHost struct {
	Host, Reason string
	At           time.Time
}

// RolloutProgress is a rollout with its effective state and host counts.
type RolloutProgress struct {
	Rollout         Rollout
	State           string
	Stage           int
	NextStageAt     *time.Time
	Counts          RolloutCounts
	RolledBackHosts []RolledBackHost
}

// Progress counts the environment's hosts against the rollout at now. Hosts on
// an unsupported platform (NodePlatformSupported, the same rule as the
// thresholds' host set) are left out entirely: they are never eligible or
// waiting, nor listed when rolled back. Windows hosts count. The
// table names are those of the nodes and osctrld status models, which this
// package must not import.
func (m *Manager) Progress(r Rollout, now time.Time) (RolloutProgress, error) {
	out := RolloutProgress{Rollout: r, State: r.EffectiveState(now), Stage: r.EffectiveStage(now), NextStageAt: r.NextStageAt(now)}
	var nodes []struct {
		UUID, Hostname, Localname, OsqueryVersion string
	}
	err := m.db.Table("osquery_nodes").
		Select("uuid, hostname, localname, osquery_version").
		Where("environment_id = ? AND deleted_at IS NULL AND "+SupportedNodePlatformSQL("platform"), r.EnvironmentID).
		Scan(&nodes).Error
	if err != nil {
		return out, err
	}
	var rejected []struct {
		NodeUUID, UpgradeReason string
		UpgradeReportedAt       *time.Time
	}
	err = m.db.Table("node_osctrld_status").
		Select("node_uuid, upgrade_reason, upgrade_reported_at").
		Where("environment_id = ? AND upgrade_result = 'rejected' AND upgrade_request_id = ?", r.EnvironmentID, r.RequestID).
		Scan(&rejected).Error
	if err != nil {
		return out, err
	}
	known := make(map[string]bool, len(nodes))
	names := make(map[string]string, len(rejected))
	rolledBack := make(map[string]bool, len(rejected))
	for _, s := range rejected {
		rolledBack[s.NodeUUID] = true
	}
	for _, n := range nodes {
		known[n.UUID] = true
		if rolledBack[n.UUID] {
			names[n.UUID] = HostName(n.Hostname, n.Localname, n.UUID)
		}
		upgraded := false
		if c, err := Compare(n.OsqueryVersion, r.Version); err == nil && c >= 0 {
			upgraded = true
			out.Counts.Upgraded++
		}
		if r.Eligible(Bucket(r.EnvironmentID, r.Version, n.UUID), now) {
			out.Counts.Eligible++
			if !upgraded && !rolledBack[n.UUID] {
				out.Counts.Waiting++
			}
		}
	}
	// Newest first with unreported times last, decided here because SQL orders
	// NULLs and time text differently per database. Sorted before truncating.
	sort.SliceStable(rejected, func(i, j int) bool {
		a, b := rejected[i].UpgradeReportedAt, rejected[j].UpgradeReportedAt
		if a == nil || b == nil {
			return a != nil && b == nil
		}
		return a.After(*b)
	})
	for _, s := range rejected {
		if !known[s.NodeUUID] {
			continue // soft-deleted, unsupported-platform or unknown node
		}
		out.Counts.RolledBack++
		if len(out.RolledBackHosts) < maxRolledBackHosts {
			h := RolledBackHost{Host: names[s.NodeUUID], Reason: truncate(s.UpgradeReason, maxReasonLen)}
			if s.UpgradeReportedAt != nil {
				h.At = *s.UpgradeReportedAt
			}
			out.RolledBackHosts = append(out.RolledBackHosts, h)
		}
	}
	return out, nil
}

// maxHostLen bounds a displayed host name, in runes.
const maxHostLen = 255

// CleanHost makes a host-reported name safe to store and log: it drops control
// and other non-printable runes (newlines, tabs, ...) and cuts to 255 runes.
func CleanHost(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsPrint(r) {
			out = append(out, r)
			if len(out) == maxHostLen {
				break
			}
		}
	}
	return string(out)
}

// HostName returns the first of the names that is non-empty once cleaned.
func HostName(names ...string) string {
	for _, v := range names {
		if c := CleanHost(v); c != "" {
			return c
		}
	}
	return ""
}

// truncate cuts a host-reported string to n runes.
func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
