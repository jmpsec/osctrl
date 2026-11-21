package santa

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/stretchr/testify/require"
)

func TestReport(t *testing.T) {
	m := newTestManager(t)
	now := testNow().UTC()
	m.now = func() time.Time { return now }
	require.NoError(t, dbutil.EnsureIndexes(m.DB, Indexes()...))
	require.True(t, m.DB.Migrator().HasIndex(&Event{}, "idx_santa_events_env_created"))

	machine := func(i int) string { return fmt.Sprintf("00000000-0000-0000-0000-%012d", i) }
	recent, stale := now.Add(-time.Hour), now.Add(-20*24*time.Hour)
	for i, mc := range []Machine{
		{MachineID: machine(1), Hostname: "quiet", AssignedMode: "MONITOR", ModeSource: "env", LastSyncAt: &recent},
		{MachineID: machine(2), Hostname: "noisy", AssignedMode: "MONITOR", ModeSource: "tag", LastSyncAt: &recent},
		{MachineID: machine(3), Hostname: "gone", AssignedMode: "MONITOR", ModeSource: "env", LastSyncAt: &stale},
		{MachineID: machine(4), Hostname: "locked", AssignedMode: "LOCKDOWN", LastSyncAt: &recent},
		{MachineID: machine(5), Hostname: "never", AssignedMode: "MONITOR"},
	} {
		mc.EnvironmentID = 1
		require.NoError(t, m.SaveMachine(&mc), i)
	}
	shaA, shaB, shaC := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	ev := func(env uint, i int, sha, decision, team string, age time.Duration) Event {
		return Event{EnvironmentID: env, MachineID: machine(i), FileSHA256: sha, FileName: "f-" + sha[:2], Decision: decision, TeamID: team, CreatedAt: now.Add(-age)}
	}
	day := 24 * time.Hour
	require.NoError(t, m.AddEvents([]Event{
		// noisy would have blocked shaC twice, and shaA once.
		ev(1, 2, shaC, "ALLOW_UNKNOWN", "", day),
		ev(1, 2, strings.ToUpper(shaC), "ALLOW_UNKNOWN", "", 2*day),
		ev(1, 2, shaA, "ALLOW_UNKNOWN", "TEAMAAAAAA", day),
		// Actual blocks, on the LOCKDOWN machine.
		ev(1, 4, shaA, "BLOCK_UNKNOWN", "teamaaaaaa", day),
		ev(1, 4, shaA, "BLOCK_UNKNOWN", "TEAMAAAAAA", day),
		ev(1, 2, shaA, "BLOCK_BINARY", "TEAMAAAAAA", day),
		ev(1, 4, shaB, "BLOCK_TEAMID", "TEAMBBBBBB", day),
		// Allowed by a rule: neither blocked nor a gap.
		ev(1, 1, shaB, "ALLOW_BINARY", "TEAMBBBBBB", day),
		// Outside the window, and in another environment.
		ev(1, 1, shaC, "ALLOW_UNKNOWN", "", 20*day),
		ev(2, 1, shaC, "BLOCK_UNKNOWN", "", day),
	}))

	_, err := m.Report(1, 0)
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = m.Report(1, MaxReportDays+1)
	require.ErrorIs(t, err, ErrInvalidRequest)

	r, err := m.Report(1, 14)
	require.NoError(t, err)
	require.Equal(t, 14, r.Days)

	// quiet is ready; noisy has would-block events; gone and never have not synced in the window.
	var got []string
	for _, c := range r.LockdownReady {
		got = append(got, fmt.Sprintf("%s:%d:%t", c.Hostname, c.WouldBlock, c.Ready))
	}
	require.Equal(t, []string{"quiet:0:true", "gone:0:false", "never:0:false", "noisy:3:false"}, got)

	require.Len(t, r.TopBlocked, 2)
	require.Equal(t, RankedBinary{SHA256: shaA, FileName: "f-a1", TeamID: r.TopBlocked[0].TeamID, Events: 3, Machines: 2}, r.TopBlocked[0])
	require.Equal(t, shaB, r.TopBlocked[1].SHA256)

	require.Equal(t, []RankedTeam{
		{TeamID: "TEAMAAAAAA", Events: 3, Machines: 2, Binaries: 1},
		{TeamID: "TEAMBBBBBB", Events: 1, Machines: 1, Binaries: 1},
	}, r.TopBlockedTeams)

	// Unknown executions, hash case folded: shaA (1 allow + 2 blocks) and shaC (2).
	require.Len(t, r.CoverageGaps, 2)
	require.Equal(t, []string{shaA, shaC}, []string{r.CoverageGaps[0].SHA256, r.CoverageGaps[1].SHA256})
	require.Equal(t, []int64{3, 2}, []int64{r.CoverageGaps[0].Events, r.CoverageGaps[1].Events})

	// A longer window reaches the old event; an empty environment reports nothing.
	r, err = m.Report(1, 30)
	require.NoError(t, err)
	require.EqualValues(t, 3, r.CoverageGaps[1].Events)
	r, err = m.Report(9, 14)
	require.NoError(t, err)
	require.Empty(t, r.LockdownReady)
	require.Empty(t, r.TopBlocked)
	require.Empty(t, r.CoverageGaps)
}

// TestReportLatency is a coarse guard for "thousands of events within normal
// page latency" on SQLite; the bound is loose so slow CI does not flake.
func TestReportLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts 20000 events")
	}
	m := newTestManager(t)
	require.NoError(t, dbutil.EnsureIndexes(m.DB, Indexes()...))
	decisions := []string{"ALLOW_UNKNOWN", "BLOCK_UNKNOWN", "ALLOW_BINARY", "BLOCK_TEAMID"}
	evs := make([]Event, 0, 20000)
	for i := range 20000 {
		evs = append(evs, Event{
			EnvironmentID: uint(1 + i%2), MachineID: fmt.Sprintf("00000000-0000-0000-0000-%012d", i%300),
			FileSHA256: fmt.Sprintf("%064x", i%700), Decision: decisions[i%4], TeamID: fmt.Sprintf("T%09d", i%50),
		})
	}
	require.NoError(t, m.AddEvents(evs))
	start := time.Now()
	_, err := m.Report(1, MaxReportDays)
	require.NoError(t, err)
	took := time.Since(start)
	t.Logf("report over 10000 events in the environment: %s", took)
	require.Less(t, took, 2*time.Second)
}

func TestReportCapsRankedLists(t *testing.T) {
	m := newTestManager(t)
	var evs []Event
	for i := range ReportTop + 5 {
		evs = append(evs, Event{EnvironmentID: 1, MachineID: testUUID, FileSHA256: fmt.Sprintf("%064x", i), Decision: "BLOCK_UNKNOWN", TeamID: fmt.Sprintf("T%09d", i)})
	}
	require.NoError(t, m.AddEvents(evs))
	r, err := m.Report(1, 1)
	require.NoError(t, err)
	require.Len(t, r.TopBlocked, ReportTop)
	require.Len(t, r.TopBlockedTeams, ReportTop)
	require.Len(t, r.CoverageGaps, ReportTop)
}

func TestReportTrendGapsAndCSV(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	a, b := "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"
	shaTeam, shaSign, shaGap := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	ev := func(machine, sha, decision string, at time.Time) Event {
		return Event{EnvironmentID: 1, MachineID: machine, FileSHA256: sha, FileName: "=cmd|calc", Decision: decision,
			TeamID: "TEAMAAAAAA", SigningID: "platform:com.example." + sha[:2], CreatedAt: at}
	}
	yesterday := now.Add(-24 * time.Hour)
	require.NoError(t, m.AddEvents([]Event{
		ev(a, shaTeam, "ALLOW_UNKNOWN", now.Add(-time.Hour)),
		ev(b, shaTeam, "ALLOW_UNKNOWN", now.Add(-2*time.Hour)),
		ev(a, shaSign, "BLOCK_UNKNOWN", now.Add(-3*time.Hour)),
		ev(a, shaGap, "BLOCK_BINARY", yesterday),
		ev(a, shaGap, "ALLOW_UNKNOWN", yesterday),
	}))
	r, err := m.Report(1, 3)
	require.NoError(t, err)

	// Trend: three UTC days, oldest first.
	require.Len(t, r.Trend, 3)
	require.True(t, r.Trend[2].Day.Equal(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)))
	require.Equal(t, TrendDay{Day: r.Trend[2].Day, Blocked: 1, WouldBlock: 2, WouldBlockMachines: 2}, r.Trend[2])
	require.Equal(t, TrendDay{Day: r.Trend[1].Day, Blocked: 1, WouldBlock: 1, WouldBlockMachines: 1}, r.Trend[1])
	require.Equal(t, TrendDay{Day: r.Trend[0].Day}, r.Trend[0])
	require.Len(t, r.CoverageGaps, 3)

	// Environment-wide rules naming a gap by signing ID or hash remove it; a tag rule does not.
	for _, rl := range []Rule{
		{Identifier: "platform:com.example.b2", RuleType: "SIGNINGID", Policy: "ALLOWLIST", Scope: "env"},
		{Identifier: shaGap, RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "env"},
		{Identifier: "TEAMAAAAAA", RuleType: "TEAMID", Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "dev"},
	} {
		rl.EnvironmentID = 1
		require.NoError(t, m.CreateRule(&rl))
	}
	r, err = m.Report(1, 3)
	require.NoError(t, err)
	require.Len(t, r.CoverageGaps, 1)
	require.Equal(t, shaTeam, r.CoverageGaps[0].SHA256)
	require.Len(t, r.TopBlocked, 2, "rules do not change what was blocked")

	var buf bytes.Buffer
	require.NoError(t, r.WriteCSV(&buf))
	rows, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Equal(t, "list", rows[0][0])
	count := map[string]int{}
	for _, row := range rows[1:] {
		require.Len(t, row, len(rows[0]))
		count[row[0]]++
		if row[0] == "coverage_gaps" {
			require.Equal(t, "'=cmd|calc", row[5], "a formula-looking name is neutralized")
		}
	}
	require.Equal(t, map[string]int{"coverage_gaps": 1, "top_blocked": 2, "top_blocked_teams": 1, "trend": 3}, count)
	require.Equal(t, []string{"trend", "2026-11-21", "", "", "", "", "", "", "1", "", "", "2", "2", "", ""}, rows[len(rows)-1])
}
