package santa

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/stretchr/testify/require"
)

func TestReport(t *testing.T) {
	m := newTestManager(t)
	now := time.Now().UTC()
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
