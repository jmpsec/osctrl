package santa

import (
	"fmt"
	"strings"
	"testing"
	"time"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/stretchr/testify/require"
)

func testNode(tags ...string) SyncNode {
	return SyncNode{EnvID: 1, NodeID: 7, UUID: strings.ToLower(testUUID), Tags: tags}
}

func hexID(i int) string { return fmt.Sprintf("%064x", i) }

func mustPreflight(t *testing.T, m *Manager, n SyncNode, clean bool) *syncv1.PreflightResponse {
	t.Helper()
	resp, err := m.Preflight(n, &syncv1.PreflightRequest{Hostname: "h", RequestCleanSync: clean})
	require.NoError(t, err)
	return resp
}

func mustPostflight(t *testing.T, m *Manager, n SyncNode) {
	t.Helper()
	_, err := m.Postflight(n, &syncv1.PostflightRequest{})
	require.NoError(t, err)
}

func TestPreflightFirstSyncIsClean(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", BatchSize: 25, EnableTransitiveRules: true, BlockUSBMount: true}))
	resp := mustPreflight(t, m, testNode(), false)
	require.Equal(t, syncv1.ClientMode_LOCKDOWN, resp.GetClientMode())
	require.NotNil(t, resp.SyncType)
	require.Equal(t, syncv1.SyncType_CLEAN_RULES, *resp.SyncType)
	require.Equal(t, uint32(25), resp.GetBatchSize())
	require.NotNil(t, resp.EnableTransitiveRules)
	require.True(t, *resp.EnableTransitiveRules)
	require.NotNil(t, resp.BlockUsbMount) //nolint:staticcheck // see sync.go
	require.True(t, *resp.BlockUsbMount)  //nolint:staticcheck // see sync.go
	require.Nil(t, resp.EnableBundles)

	mc, err := m.Machine(1, strings.ToUpper(testUUID))
	require.NoError(t, err)
	require.Equal(t, uint(7), mc.NodeID)
	require.Equal(t, "CLEAN_RULES", mc.PendingSyncType)
	require.NotNil(t, mc.LastPreflightAt)
}

func TestPreflightDefaultsOmitBatchAndFalseFlags(t *testing.T) {
	m := newTestManager(t)
	resp := mustPreflight(t, m, testNode(), false)
	require.Equal(t, syncv1.ClientMode_MONITOR, resp.GetClientMode())
	require.Zero(t, resp.GetBatchSize())
	require.NotNil(t, resp.EnableTransitiveRules)
	require.False(t, *resp.EnableTransitiveRules)
	require.NotNil(t, resp.BlockUsbMount) //nolint:staticcheck // see sync.go
	require.False(t, *resp.BlockUsbMount) //nolint:staticcheck // see sync.go
}

func TestPreflightUnchangedIsNormal(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.CreateRule(testRule(1)))
	n := testNode()
	mustPreflight(t, m, n, false)
	mustPostflight(t, m, n)

	resp := mustPreflight(t, m, n, false)
	require.Equal(t, syncv1.SyncType_NORMAL, *resp.SyncType)
	rd, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{})
	require.NoError(t, err)
	require.Empty(t, rd.Rules)
	require.Empty(t, rd.Cursor)

	resp = mustPreflight(t, m, n, true)
	require.Equal(t, syncv1.SyncType_CLEAN_RULES, *resp.SyncType)
}

func TestPreflightRuleChangeTriggersClean(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	mustPostflight(t, m, n)
	require.NoError(t, m.CreateRule(testRule(1)))
	require.Equal(t, syncv1.SyncType_CLEAN_RULES, *mustPreflight(t, m, n, false).SyncType)
}

func TestPreflightTagChangeTriggersClean(t *testing.T) {
	m := newTestManager(t)
	r := testRule(1)
	r.Scope, r.ScopeValue = "tag", "prod"
	require.NoError(t, m.CreateRule(r))
	mustPreflight(t, m, testNode(), false)
	mustPostflight(t, m, testNode())
	require.Equal(t, syncv1.SyncType_NORMAL, *mustPreflight(t, m, testNode(), false).SyncType)
	require.Equal(t, syncv1.SyncType_CLEAN_RULES, *mustPreflight(t, m, testNode("prod"), false).SyncType)
}

func seedRules(t *testing.T, m *Manager, n int) {
	t.Helper()
	rules := make([]Rule, n)
	for i := range rules {
		rules[i] = Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: hexID(i), Policy: "BLOCKLIST", Scope: "env", CustomMsg: "m", CustomURL: "u", CELExpr: "c"}
	}
	require.NoError(t, m.DB.CreateInBatches(&rules, 100).Error)
}

func TestRuleDownloadPaginates(t *testing.T) {
	m := newTestManager(t)
	seedRules(t, m, 1201)
	n := testNode()
	mustPreflight(t, m, n, false)

	var sizes []int
	var cursors []string
	cursor := ""
	var first *syncv1.Rule
	for range 5 {
		resp, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{Cursor: cursor})
		require.NoError(t, err)
		if first == nil {
			first = resp.Rules[0]
		}
		sizes = append(sizes, len(resp.Rules))
		cursors = append(cursors, resp.Cursor)
		if resp.Cursor == "" {
			break
		}
		cursor = resp.Cursor
	}
	require.Equal(t, []int{500, 500, 201}, sizes)
	require.Equal(t, []string{"500", "1000", ""}, cursors)
	require.Equal(t, hexID(0), first.Identifier)
	require.Equal(t, syncv1.Policy_BLOCKLIST, first.Policy)
	require.Equal(t, syncv1.RuleType_BINARY, first.RuleType)
	require.Equal(t, "m", first.CustomMsg)
	require.Equal(t, "u", first.CustomUrl)
	require.Equal(t, "c", first.CelExpr)
}

func TestRuleDownloadBadCursor(t *testing.T) {
	m := newTestManager(t)
	seedRules(t, m, 3)
	n := testNode()
	mustPreflight(t, m, n, false)
	for _, c := range []string{"abc", "-1", "4", "1.5"} {
		_, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{Cursor: c})
		require.Error(t, err, c)
	}
	_, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{Cursor: "3"})
	require.NoError(t, err)
}

func TestRuleDownloadUnmappableStoredValueErrors(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.DB.Create(&Rule{EnvironmentID: 1, RuleType: "BINARY", Identifier: hexID(1), Policy: "BOGUS", Scope: "env"}).Error)
	n := testNode()
	mustPreflight(t, m, n, false)
	_, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{})
	require.Error(t, err)
}

func TestPostflightStoresPreflightDigest(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.CreateRule(testRule(1)))
	n := testNode()
	mustPreflight(t, m, n, false)
	rules, err := m.EffectiveRules(1, n.UUID, nil)
	require.NoError(t, err)
	want := RulesDigest(rules)

	r2 := testRule(1)
	r2.Identifier = strings.Repeat("cd", 32)
	require.NoError(t, m.CreateRule(r2))
	mustPostflight(t, m, n)

	mc, err := m.Machine(1, strings.ToUpper(testUUID))
	require.NoError(t, err)
	require.Equal(t, want, mc.AppliedDigest)
	require.Equal(t, "MONITOR", mc.ClientMode)
	require.NotNil(t, mc.LastSyncAt)
	require.Equal(t, syncv1.SyncType_CLEAN_RULES, *mustPreflight(t, m, n, false).SyncType)
}

func TestStagesWithoutPreflightFail(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	_, err := m.RuleDownload(n, &syncv1.RuleDownloadRequest{})
	require.ErrorIs(t, err, ErrNoPreflight)
	_, err = m.Postflight(n, &syncv1.PostflightRequest{})
	require.ErrorIs(t, err, ErrNoPreflight)
	_, err = m.EventUpload(n, &syncv1.EventUploadRequest{})
	require.ErrorIs(t, err, ErrNoPreflight)
}

func TestEventUploadStoresBlockedEvent(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	long := strings.Repeat("é", 200) // 400 bytes
	_, err := m.EventUpload(n, &syncv1.EventUploadRequest{Events: []*syncv1.Event{{
		FileSha256: hexID(1), FilePath: long, FileName: "x", ExecutingUser: "u",
		ExecutionTime: 1700000000.25, Decision: syncv1.Decision_BLOCK_BINARY,
		TeamId: "T", SigningId: "S", Cdhash: "C", FileBundleId: "B",
	}}})
	require.NoError(t, err)

	evs, total, err := m.Events(1, 1, 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	e := evs[0]
	require.Equal(t, uint(7), e.NodeID)
	require.Equal(t, strings.ToUpper(testUUID), e.MachineID)
	require.Equal(t, "BLOCK_BINARY", e.Decision)
	require.Equal(t, hexID(1), e.FileSHA256)
	require.Equal(t, "T", e.TeamID)
	require.Equal(t, "B", e.BundleID)
	require.True(t, e.ExecutedAt.Equal(time.Unix(1700000000, 250000000)))
	require.LessOrEqual(t, len(e.FilePath), 255)
	require.Equal(t, strings.Repeat("é", 127), e.FilePath)
}

func TestTruncate(t *testing.T) {
	require.Equal(t, "abc", truncate("abc", 255))
	require.Equal(t, "ab", truncate("abé", 3))
}
