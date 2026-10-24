package nodeconfig

import (
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evID(n int, c string) string { return strings.Repeat("1", n) + ":" + strings.Repeat(c, 64) }

var reportAt = time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

func downReport(flagsEv string) types.OsctrldStatusRequest {
	ds := reportAt.Add(-5 * time.Minute)
	return types.OsctrldStatusRequest{
		UUID:       "n1",
		DownSince:  &ds,
		Flags:      types.OsctrldRollback{Stage: "exhausted", EventID: flagsEv},
		Extensions: types.OsctrldRollback{Stage: "none"},
	}
}

func TestRecordReportStoresState(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	ev := evID(3, "a")
	r := downReport(ev)
	r.Extensions = types.OsctrldRollback{Stage: "restored", EventID: evID(2, "b")}
	nev, err := m.RecordReport("n1", 7, r, reportAt)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"flags", "extensions"}, nev)
	st, err := m.Status("n1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.EqualValues(t, 7, st.EnvironmentID)
	require.NotNil(t, st.OsqueryRunning)
	assert.False(t, *st.OsqueryRunning)
	require.NotNil(t, st.DownSince)
	assert.True(t, r.DownSince.Equal(*st.DownSince))
	require.NotNil(t, st.ReportedAt)
	assert.True(t, reportAt.Equal(*st.ReportedAt))
	assert.Equal(t, "exhausted", st.FlagsStage)
	assert.Equal(t, "restored", st.ExtensionsStage)
	assert.Equal(t, ev, st.FlagsEventID)
	assert.Equal(t, evID(2, "b"), st.ExtensionsEventID)
}

func TestRecordReportRepeatedEventIsNotNew(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	r := downReport(evID(3, "a"))
	nev, err := m.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	assert.Equal(t, []string{"flags"}, nev)
	nev, err = m.RecordReport("n1", 1, r, reportAt.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, nev)
	// a different event id is new again
	nev, err = m.RecordReport("n1", 1, downReport(evID(4, "c")), reportAt.Add(2*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, []string{"flags"}, nev)
}

func TestRecordReportTwoManagersCountEventOnce(t *testing.T) {
	m1, cm, _, _ := newTestFlagsManager(t)
	m2, err := newFlagsManagerWithStore(cm.db, newFakeStore())
	require.NoError(t, err)
	r := downReport(evID(3, "a"))
	n1, err := m1.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	n2, err := m2.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	assert.Equal(t, 1, len(n1)+len(n2))
}

func TestRecordReportDropsInvalidStageAndEventID(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	good := evID(2, "b")
	_, err := m.RecordReport("n1", 1, types.OsctrldStatusRequest{
		Flags:      types.OsctrldRollback{Stage: "exhausted", EventID: evID(3, "a")},
		Extensions: types.OsctrldRollback{Stage: "restored", EventID: good},
	}, reportAt)
	require.NoError(t, err)

	cases := []types.OsctrldStatusRequest{
		{Flags: types.OsctrldRollback{Stage: "bogus", EventID: evID(5, "c")}, Extensions: types.OsctrldRollback{Stage: "restored", EventID: good}},
		{Flags: types.OsctrldRollback{Stage: "exhausted", EventID: "nothex"}, Extensions: types.OsctrldRollback{Stage: "restored", EventID: good}},
		{Flags: types.OsctrldRollback{Stage: "exhausted", EventID: ""}, Extensions: types.OsctrldRollback{Stage: "restored", EventID: good}},
	}
	for _, r := range cases {
		r.OsqueryRunning = true
		nev, err := m.RecordReport("n1", 1, r, reportAt.Add(time.Minute))
		require.NoError(t, err)
		assert.Empty(t, nev)
		st, err := m.Status("n1")
		require.NoError(t, err)
		assert.Equal(t, "exhausted", st.FlagsStage)
		assert.Equal(t, evID(3, "a"), st.FlagsEventID)
		assert.Equal(t, "restored", st.ExtensionsStage)
		assert.Equal(t, good, st.ExtensionsEventID)
		require.NotNil(t, st.OsqueryRunning)
		assert.True(t, *st.OsqueryRunning)
	}
}

func TestRecordReportCreatesRowWithoutFetch(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	_, err := m.RecordReport("n1", 3, types.OsctrldStatusRequest{OsqueryRunning: true,
		Flags: types.OsctrldRollback{Stage: "none"}, Extensions: types.OsctrldRollback{Stage: "none"}}, reportAt)
	require.NoError(t, err)
	st, err := m.Status("n1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.LastFetchedAt.IsZero())
	assert.EqualValues(t, 3, st.EnvironmentID)
	assert.Nil(t, st.DownSince)
}

func TestRecordReportIgnoresAbsurdDownSince(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	bad := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := m.RecordReport("n1", 1, types.OsctrldStatusRequest{DownSince: &bad}, reportAt)
	require.NoError(t, err)
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.Nil(t, st.DownSince)
}

func TestRecordFetchKeepsReportFields(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	ev := evID(3, "a")
	_, err := m.RecordReport("n1", 1, downReport(ev), reportAt)
	require.NoError(t, err)
	require.NoError(t, m.RecordFetch("n1", 1, reportAt.Add(time.Minute), &types.OsctrldApplyStatus{Result: "applied", At: reportAt}))
	st, err := m.Status("n1")
	require.NoError(t, err)
	require.NotNil(t, st.OsqueryRunning)
	assert.False(t, *st.OsqueryRunning)
	require.NotNil(t, st.DownSince)
	require.NotNil(t, st.ReportedAt)
	assert.Equal(t, "exhausted", st.FlagsStage)
	assert.Equal(t, ev, st.FlagsEventID)
}

func TestCountDownIgnoresStaleAndRunning(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	now := reportAt
	rep := func(uuid string, running bool, at time.Time) {
		_, err := m.RecordReport(uuid, 1, types.OsctrldStatusRequest{OsqueryRunning: running}, at)
		require.NoError(t, err)
	}
	rep("down", false, now.Add(-time.Minute))
	rep("edge", false, now.Add(-ReportFreshness))
	rep("stale", false, now.Add(-16*time.Minute))
	rep("up", true, now)
	got, err := m.CountDown(now)
	require.NoError(t, err)
	assert.Equal(t, map[uint]int{1: 2}, got)
}

func TestCountDownGroupsByEnvironment(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	for uuid, env := range map[string]uint{"a": 1, "b": 1, "c": 2} {
		_, err := m.RecordReport(uuid, env, types.OsctrldStatusRequest{}, reportAt)
		require.NoError(t, err)
	}
	got, err := m.CountDown(reportAt)
	require.NoError(t, err)
	assert.Equal(t, map[uint]int{1: 2, 2: 1}, got)
}

func TestRecordReportCountsFirstEventOnPreMigrationRow(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	require.NoError(t, m.RecordFetch("n1", 1, reportAt, nil))
	require.NoError(t, m.db.Exec("UPDATE node_osctrld_status SET flags_event_id = NULL, extensions_event_id = NULL, flags_stage = NULL, extensions_stage = NULL WHERE node_uuid = ?", "n1").Error)
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.Equal(t, "", st.FlagsStage)

	r := downReport(evID(3, "a"))
	nev, err := m.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	assert.Equal(t, []string{"flags"}, nev)
	nev, err = m.RecordReport("n1", 1, r, reportAt.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, nev)
}

func upReport(u types.OsctrldUpgrade) types.OsctrldStatusRequest {
	r := downReport("")
	r.Flags = types.OsctrldRollback{Stage: "none"}
	r.Upgrade = &u
	return r
}

var rejectedUp = types.OsctrldUpgrade{Result: "rejected", Version: "5.13.0", Reason: "version_not_reported",
	RequestID: strings.Repeat("a", 32), EventID: evID(3, "a")}

func TestRecordReportStoresUpgrade(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	nev, err := m.RecordReport("n1", 1, upReport(rejectedUp), reportAt)
	require.NoError(t, err)
	assert.Equal(t, []string{"upgrade"}, nev)
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.Equal(t, "rejected", st.UpgradeResult)
	assert.Equal(t, "5.13.0", st.UpgradeVersion)
	assert.Equal(t, "version_not_reported", st.UpgradeReason)
	assert.Equal(t, rejectedUp.RequestID, st.UpgradeRequestID)
	assert.Equal(t, rejectedUp.EventID, st.UpgradeEventID)
	require.NotNil(t, st.UpgradeReportedAt)
	assert.True(t, reportAt.Equal(*st.UpgradeReportedAt))

	// ok overwrites and is never a rollback event; a report without upgrade keeps it
	nev, err = m.RecordReport("n1", 1, upReport(types.OsctrldUpgrade{Result: "ok", Version: "5.13.0"}), reportAt.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, nev)
	st, _ = m.Status("n1")
	assert.Equal(t, "ok", st.UpgradeResult)
	assert.Empty(t, st.UpgradeReason)
	_, err = m.RecordReport("n1", 1, downReport(""), reportAt.Add(2*time.Minute))
	require.NoError(t, err)
	st, _ = m.Status("n1")
	assert.Equal(t, "ok", st.UpgradeResult)
}

func TestRecordReportUpgradeRollbackCountedOnce(t *testing.T) {
	m1, cm, _, _ := newTestFlagsManager(t)
	m2, err := newFlagsManagerWithStore(cm.db, newFakeStore())
	require.NoError(t, err)
	r := upReport(rejectedUp)
	n1, err := m1.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	n1b, err := m1.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	n2, err := m2.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	assert.Equal(t, 1, len(n1)+len(n1b)+len(n2))
	// a new event id counts again
	u := rejectedUp
	u.EventID = evID(4, "b")
	n, err := m1.RecordReport("n1", 1, upReport(u), reportAt)
	require.NoError(t, err)
	assert.Equal(t, []string{"upgrade"}, n)
}

func TestRecordReportUpgradeNullColumnsFirstEventIsNew(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	require.NoError(t, m.RecordFetch("n1", 1, reportAt, nil))
	require.NoError(t, m.db.Exec("UPDATE node_osctrld_status SET upgrade_event_id = NULL, upgrade_result = NULL WHERE node_uuid = ?", "n1").Error)
	r := upReport(rejectedUp)
	nev, err := m.RecordReport("n1", 1, r, reportAt)
	require.NoError(t, err)
	assert.Equal(t, []string{"upgrade"}, nev)
	nev, err = m.RecordReport("n1", 1, r, reportAt.Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, nev)
}

func TestRecordReportDropsInvalidUpgrade(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	_, err := m.RecordReport("n1", 1, upReport(rejectedUp), reportAt)
	require.NoError(t, err)
	mod := func(f func(u *types.OsctrldUpgrade)) types.OsctrldUpgrade { u := rejectedUp; f(&u); return u }
	cases := map[string]types.OsctrldUpgrade{
		"bad result":          mod(func(u *types.OsctrldUpgrade) { u.Result = "bogus" }),
		"bad reason":          mod(func(u *types.OsctrldUpgrade) { u.Reason = "nope" }),
		"bad version":         mod(func(u *types.OsctrldUpgrade) { u.Version = "5.x" }),
		"bad event id":        mod(func(u *types.OsctrldUpgrade) { u.EventID = "nothex" }),
		"no event id":         mod(func(u *types.OsctrldUpgrade) { u.EventID = "" }),
		"bad request id":      mod(func(u *types.OsctrldUpgrade) { u.RequestID = "XYZ" }),
		"ok with reason":      {Result: "ok", Version: "5.13.0", Reason: "rolled_back"},
		"skipped no reason":   {Result: "skipped"},
		"ok with event id":    {Result: "ok", Version: "5.13.0", EventID: evID(3, "c")},
		"event id on skipped": {Result: "skipped", Version: "5.13.0", Reason: "osqueryd_not_running", EventID: evID(3, "c")},
		"rejected no reason":  mod(func(u *types.OsctrldUpgrade) { u.Reason = "" }),
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			assert.False(t, ValidUpgrade(u))
			r := upReport(u)
			r.OsqueryRunning = true
			nev, err := m.RecordReport("n1", 1, r, reportAt.Add(time.Minute))
			require.NoError(t, err)
			assert.Empty(t, nev)
			st, err := m.Status("n1")
			require.NoError(t, err)
			assert.Equal(t, rejectedUp.EventID, st.UpgradeEventID)
			assert.Equal(t, "rejected", st.UpgradeResult)
			assert.Equal(t, "5.13.0", st.UpgradeVersion)
			require.NotNil(t, st.OsqueryRunning)
			assert.True(t, *st.OsqueryRunning, "rest of the report still stored")
		})
	}
	assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "skipped", Reason: "no_target"}))
	assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "skipped", Version: "5.13.0", Reason: "osqueryd_not_running"}))
}

func TestRecordFetchKeepsUpgradeFields(t *testing.T) {
	m, _, _, _ := newTestFlagsManager(t)
	_, err := m.RecordReport("n1", 1, upReport(rejectedUp), reportAt)
	require.NoError(t, err)
	require.NoError(t, m.RecordFetch("n1", 1, reportAt.Add(time.Minute), &types.OsctrldApplyStatus{Result: "applied", At: reportAt}))
	st, err := m.Status("n1")
	require.NoError(t, err)
	assert.Equal(t, "rejected", st.UpgradeResult)
	assert.Equal(t, rejectedUp.EventID, st.UpgradeEventID)
	require.NotNil(t, st.UpgradeReportedAt)
}

func TestValidUpgradeAcceptsRolloutReasons(t *testing.T) {
	for _, reason := range []string{"rollout_pending", "rollout_paused"} {
		assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "skipped", Reason: reason, RequestID: strings.Repeat("a", 32)}), reason)
		assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "skipped", Version: "5.13.0", Reason: reason}), reason)
		assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "rejected", Version: "5.13.0", Reason: reason, EventID: evID(3, "c")}), reason)
	}
}

func TestValidUpgradeAcceptsRollbackUnavailable(t *testing.T) {
	assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "rejected", Version: "5.13.0", Reason: "rollback_unavailable", RequestID: strings.Repeat("a", 32), EventID: evID(3, "c")}))
	assert.True(t, ValidUpgrade(types.OsctrldUpgrade{Result: "skipped", Reason: "rollback_unavailable"}))
}
