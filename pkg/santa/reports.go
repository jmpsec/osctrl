package santa

import (
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
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
	SHA256    string `json:"sha256"`
	FileName  string `json:"file_name"`
	TeamID    string `json:"team_id"`
	SigningID string `json:"signing_id"`
	CDHash    string `json:"cd_hash"`
	Events    int64  `json:"events"`
	Machines  int64  `json:"machines"`
}

// TrendDay is one UTC day of the window: blocks and would-be blocks.
type TrendDay struct {
	Day     time.Time `json:"day"`
	Blocked int64     `json:"blocked"`
	// ALLOW_UNKNOWN events, and the machines that had any
	WouldBlock         int64 `json:"would_block"`
	WouldBlockMachines int64 `json:"would_block_machines"`
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
	// Most executed binaries that no rule decided (ALLOW_UNKNOWN or BLOCK_UNKNOWN),
	// leaving out those an environment-wide rule now names
	CoverageGaps []RankedBinary `json:"coverage_gaps"`
	// One entry per UTC day of the window, oldest first
	Trend []TrendDay `json:"trend"`
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
	binaries := func(q *gorm.DB, limit int) ([]RankedBinary, error) {
		var out []RankedBinary
		err := q.Where("file_sha256 <> ''").
			Select("LOWER(file_sha256) AS sha256, MAX(file_name) AS file_name, MAX(team_id) AS team_id, " +
				"MAX(signing_id) AS signing_id, MAX(cd_hash) AS cd_hash, " +
				"COUNT(*) AS events, COUNT(DISTINCT machine_id) AS machines").
			Group("LOWER(file_sha256)").Order("events DESC, sha256").Limit(limit).Scan(&out).Error
		return out, err
	}
	var err error
	if r.TopBlocked, err = binaries(window().Where("decision LIKE ?", "BLOCK%"), ReportTop); err != nil {
		return Report{}, err
	}
	// Events keep the decision of their time: a rule added since may cover a gap.
	// ponytail: reads 5x the list and filters; a gap past that is missed when
	// most of the top ones are covered.
	gaps, err := binaries(window().Where("decision IN ?", unknownDecisions), 5*ReportTop)
	if err != nil {
		return Report{}, err
	}
	if r.CoverageGaps, err = m.uncovered(envID, gaps); err != nil {
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
	if r.Trend, err = m.trend(envID, now, days); err != nil {
		return Report{}, err
	}
	return r, nil
}

// uncovered drops the binaries that an environment-wide rule now names by
// hash, team ID, signing ID or CDHash, and caps the rest at ReportTop.
// Certificate rules are not checked: the ranked list has no leaf certificate.
func (m *Manager) uncovered(envID uint, bins []RankedBinary) ([]RankedBinary, error) {
	var rules []Rule
	if err := m.DB.Select("rule_type", "identifier").
		Where("environment_id = ? AND scope = ? AND rule_type IN ?", envID, "env", []string{"BINARY", "TEAMID", "SIGNINGID", "CDHASH"}).
		Find(&rules).Error; err != nil {
		return nil, err
	}
	named := make(map[string]bool, len(rules))
	for _, rl := range rules {
		named[rl.RuleType+"\x00"+strings.ToLower(rl.Identifier)] = true
	}
	covered := func(b RankedBinary) bool {
		for typ, id := range map[string]string{"BINARY": b.SHA256, "TEAMID": b.TeamID, "SIGNINGID": b.SigningID, "CDHASH": b.CDHash} {
			if id != "" && named[typ+"\x00"+strings.ToLower(id)] {
				return true
			}
		}
		return false
	}
	out := slices.DeleteFunc(bins, covered)
	return out[:min(len(out), ReportTop)], nil
}

// trend counts blocks and would-be blocks per UTC day, oldest first. One
// indexed range query per day keeps the grouping portable across databases.
func (m *Manager) trend(envID uint, now time.Time, days int) ([]TrendDay, error) {
	today := now.UTC().Truncate(24 * time.Hour)
	out := make([]TrendDay, 0, days)
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		var c struct{ Blocked, WouldBlock, WouldBlockMachines int64 }
		if err := m.DB.Model(&Event{}).
			Where("environment_id = ? AND created_at >= ? AND created_at < ?", envID, day, day.AddDate(0, 0, 1)).
			Select("COALESCE(SUM(CASE WHEN decision LIKE 'BLOCK%' THEN 1 ELSE 0 END), 0) AS blocked, " +
				"COALESCE(SUM(CASE WHEN decision = 'ALLOW_UNKNOWN' THEN 1 ELSE 0 END), 0) AS would_block, " +
				"COUNT(DISTINCT CASE WHEN decision = 'ALLOW_UNKNOWN' THEN machine_id END) AS would_block_machines").
			Scan(&c).Error; err != nil {
			return nil, err
		}
		out = append(out, TrendDay{Day: day, Blocked: c.Blocked, WouldBlock: c.WouldBlock, WouldBlockMachines: c.WouldBlockMachines})
	}
	return out, nil
}

// csvCell neutralizes a client-written value that a spreadsheet would run
// as a formula.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// WriteCSV writes the report as one CSV table; the list column names the
// section of each row, and columns that do not apply to it are empty.
func (r Report) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	itoa := func(n int64) string { return strconv.FormatInt(n, 10) }
	_ = cw.Write([]string{"list", "day", "machine_id", "hostname", "sha256", "file_name", "team_id",
		"events", "blocked", "machines", "binaries", "would_block", "would_block_machines", "ready", "last_sync_at"})
	for _, c := range r.LockdownReady {
		last := ""
		if c.LastSyncAt != nil {
			last = c.LastSyncAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{"lockdown_ready", "", csvCell(c.MachineID), csvCell(c.Hostname), "", "", "",
			"", "", "", "", itoa(c.WouldBlock), "", strconv.FormatBool(c.Ready), last})
	}
	for _, l := range []struct {
		name string
		bins []RankedBinary
	}{{"coverage_gaps", r.CoverageGaps}, {"top_blocked", r.TopBlocked}} {
		for _, b := range l.bins {
			_ = cw.Write([]string{l.name, "", "", "", csvCell(b.SHA256), csvCell(b.FileName), csvCell(b.TeamID),
				itoa(b.Events), "", itoa(b.Machines), "", "", "", "", ""})
		}
	}
	for _, t := range r.TopBlockedTeams {
		_ = cw.Write([]string{"top_blocked_teams", "", "", "", "", "", csvCell(t.TeamID),
			itoa(t.Events), "", itoa(t.Machines), itoa(t.Binaries), "", "", "", ""})
	}
	for _, d := range r.Trend {
		_ = cw.Write([]string{"trend", d.Day.Format(time.DateOnly), "", "", "", "", "",
			"", itoa(d.Blocked), "", "", itoa(d.WouldBlock), itoa(d.WouldBlockMachines), "", ""})
	}
	cw.Flush()
	return cw.Error()
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
