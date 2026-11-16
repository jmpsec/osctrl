package santa

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/dbutil"
	"gorm.io/gorm"
)

const (
	// MaxReportDays is the longest report window; events are kept 30 days.
	MaxReportDays = 30
	// DefaultReportDays is the window used when none is given.
	DefaultReportDays = 14
	// ReportTop caps each ranked list.
	ReportTop = 20
)

// Indexes are the Santa indexes built in the background at startup
// (dbutil.BuildIndexes), so a large events table does not hold up AutoMigrate.
func Indexes() []dbutil.Index {
	return []dbutil.Index{
		// Every report reads one environment's events in a time window.
		{Model: &Event{}, Name: "idx_santa_events_env_created", Columns: []string{"environment_id", "created_at"}},
	}
}

// LockdownCandidate is a machine osctrl keeps in MONITOR, with the executions
// it allowed in the window that LOCKDOWN would have blocked.
type LockdownCandidate struct {
	MachineID  string     `json:"machine_id"`
	Hostname   string     `json:"hostname"`
	ModeSource string     `json:"mode_source"`
	LastSyncAt *time.Time `json:"last_sync_at"`
	// ALLOW_UNKNOWN events in the window: executions no rule allowed
	WouldBlock int64 `json:"would_block"`
	// No would-block execution and a sync within the window
	Ready bool `json:"ready"`
}

// RankedBinary is a file hash ranked by its events in the window.
type RankedBinary struct {
	SHA256   string `json:"sha256"`
	FileName string `json:"file_name"`
	TeamID   string `json:"team_id"`
	Events   int64  `json:"events"`
	Machines int64  `json:"machines"`
}

// RankedTeam is a team ID ranked by its events in the window.
type RankedTeam struct {
	TeamID   string `json:"team_id"`
	Events   int64  `json:"events"`
	Machines int64  `json:"machines"`
	Binaries int64  `json:"binaries"`
}

// Report is computed from the events received in the last Days days.
type Report struct {
	Days  int       `json:"days"`
	Since time.Time `json:"since"`
	// Machines assigned MONITOR at their last preflight, ready ones first
	LockdownReady []LockdownCandidate `json:"lockdown_ready"`
	// Most blocked binaries and team IDs
	TopBlocked      []RankedBinary `json:"top_blocked"`
	TopBlockedTeams []RankedTeam   `json:"top_blocked_teams"`
	// Most executed binaries that no rule decided (ALLOW_UNKNOWN or BLOCK_UNKNOWN)
	CoverageGaps []RankedBinary `json:"coverage_gaps"`
}

// unknownDecisions are executions no rule decided: allowed in MONITOR,
// blocked in LOCKDOWN.
var unknownDecisions = []string{"ALLOW_UNKNOWN", "BLOCK_UNKNOWN"}

// Report computes the environment's Santa report over the last days days
// (1 to MaxReportDays). The window is on the time osctrl received each event,
// not the client's execution time.
func (m *Manager) Report(envID uint, days int) (Report, error) {
	if days < 1 || days > MaxReportDays {
		return Report{}, fmt.Errorf("%w: days must be 1 to %d", ErrInvalidRequest, MaxReportDays)
	}
	now := m.now()
	r := Report{Days: days, Since: now.Add(-time.Duration(days) * 24 * time.Hour)}
	window := func() *gorm.DB {
		return m.DB.Model(&Event{}).Where("environment_id = ? AND created_at >= ?", envID, r.Since)
	}
	binaries := func(q *gorm.DB) ([]RankedBinary, error) {
		var out []RankedBinary
		err := q.Where("file_sha256 <> ''").
			Select("LOWER(file_sha256) AS sha256, MAX(file_name) AS file_name, MAX(team_id) AS team_id, " +
				"COUNT(*) AS events, COUNT(DISTINCT machine_id) AS machines").
			Group("LOWER(file_sha256)").Order("events DESC, sha256").Limit(ReportTop).Scan(&out).Error
		return out, err
	}
	var err error
	if r.TopBlocked, err = binaries(window().Where("decision LIKE ?", "BLOCK%")); err != nil {
		return Report{}, err
	}
	if r.CoverageGaps, err = binaries(window().Where("decision IN ?", unknownDecisions)); err != nil {
		return Report{}, err
	}
	if err := window().Where("decision LIKE ? AND team_id <> ''", "BLOCK%").
		Select("UPPER(team_id) AS team_id, COUNT(*) AS events, COUNT(DISTINCT machine_id) AS machines, " +
			"COUNT(DISTINCT LOWER(file_sha256)) AS binaries").
		Group("UPPER(team_id)").Order("events DESC, team_id").Limit(ReportTop).Scan(&r.TopBlockedTeams).Error; err != nil {
		return Report{}, err
	}
	if r.LockdownReady, err = m.lockdownCandidates(envID, r.Since, window); err != nil {
		return Report{}, err
	}
	return r, nil
}

func (m *Manager) lockdownCandidates(envID uint, since time.Time, window func() *gorm.DB) ([]LockdownCandidate, error) {
	var machines []Machine
	if err := m.DB.Where("environment_id = ? AND assigned_mode = ?", envID, "MONITOR").Find(&machines).Error; err != nil {
		return nil, err
	}
	var counts []struct {
		MachineID string
		N         int64
	}
	if err := window().Where("decision = ?", "ALLOW_UNKNOWN").
		Select("machine_id, COUNT(*) AS n").Group("machine_id").Scan(&counts).Error; err != nil {
		return nil, err
	}
	wouldBlock := make(map[string]int64, len(counts))
	for _, c := range counts {
		wouldBlock[strings.ToUpper(c.MachineID)] += c.N
	}
	out := make([]LockdownCandidate, 0, len(machines))
	for _, mc := range machines {
		c := LockdownCandidate{
			MachineID: mc.MachineID, Hostname: mc.Hostname, ModeSource: mc.ModeSource, LastSyncAt: mc.LastSyncAt,
			WouldBlock: wouldBlock[strings.ToUpper(mc.MachineID)],
		}
		// A machine that has not synced in the window has reported nothing to judge it by.
		c.Ready = c.WouldBlock == 0 && mc.LastSyncAt != nil && !mc.LastSyncAt.Before(since)
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ready != out[j].Ready {
			return out[i].Ready
		}
		if out[i].WouldBlock != out[j].WouldBlock {
			return out[i].WouldBlock < out[j].WouldBlock
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out, nil
}
