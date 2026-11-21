package santa

import (
	"strings"
	"testing"
	"time"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/stretchr/testify/require"
)

func TestPreflightFileAccessOverride(t *testing.T) {
	for _, tt := range []struct {
		action string
		want   *syncv1.FileAccessAction
	}{
		{"", nil},
		{"NONE", syncv1.FileAccessAction_NONE.Enum()},
		{"AUDIT_ONLY", syncv1.FileAccessAction_AUDIT_ONLY.Enum()},
		{"DISABLE", syncv1.FileAccessAction_DISABLE.Enum()},
	} {
		m := newTestManager(t)
		require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", OverrideFileAccessAction: tt.action}))
		require.Equal(t, tt.want, mustPreflight(t, m, testNode(), false).OverrideFileAccessAction, tt.action)
	}
}

func TestValidateFileAccessOverride(t *testing.T) {
	for _, a := range []string{"none", "Disable", "UNSPECIFIED", "FILE_ACCESS_ACTION_UNSPECIFIED", "BLOCK"} {
		require.Error(t, ValidateConfig(&EnvConfig{ClientMode: "MONITOR", OverrideFileAccessAction: a}), a)
	}
}

func TestEventUploadStoresFileAccessEvents(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	chain := make([]*syncv1.Process, 12)
	for i := range chain {
		chain[i] = &syncv1.Process{Pid: int32(100 + i), FilePath: "/usr/bin/p", FileSha256: hexID(i), SigningId: "platform:p", TeamId: "T"}
	}
	_, err := m.EventUpload(n, &syncv1.EventUploadRequest{
		Events: []*syncv1.Event{{FileSha256: hexID(1), Decision: syncv1.Decision_BLOCK_BINARY}},
		FileAccessEvents: []*syncv1.FileAccessEvent{nil, {
			RuleName: "ChromeCookies", RuleVersion: "v2", Target: "/Users/u/Library/Cookies/" + strings.Repeat("a", 2000),
			ProcessChain: chain, AccessTime: 1700000000.5, Decision: syncv1.FileAccessDecision_FILE_ACCESS_DECISION_DENIED,
		}},
	})
	require.NoError(t, err)

	evs, total, err := m.FileAccessEvents(1, 1, 10, FileAccessFilter{MachineID: strings.ToLower(testUUID)})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	e := evs[0]
	require.Equal(t, uint(7), e.NodeID)
	require.Equal(t, strings.ToUpper(testUUID), e.MachineID)
	require.Equal(t, "ChromeCookies", e.RuleName)
	require.Equal(t, "v2", e.RuleVersion)
	require.Equal(t, "DENIED", e.Decision)
	require.Len(t, e.Target, 1024)
	require.True(t, e.AccessedAt.Equal(time.Unix(1700000000, 500000000)))
	require.Len(t, e.ProcessChain, maxChainProcs)
	require.Equal(t, Process{Pid: 100, FilePath: "/usr/bin/p", FileSHA256: hexID(0), SigningID: "platform:p", TeamID: "T"}, e.ProcessChain[0])

	// The execution event is stored too, and other environments see neither.
	_, total, err = m.Events(1, 1, 10, EventFilter{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	_, total, err = m.FileAccessEvents(2, 1, 10, FileAccessFilter{})
	require.NoError(t, err)
	require.Zero(t, total)

	gone, err := m.PruneEvents(time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 2, gone)
}

func TestFileAccessFilter(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	mustPreflight(t, m, n, false)
	ev := func(target, proc string, d syncv1.FileAccessDecision) *syncv1.FileAccessEvent {
		return &syncv1.FileAccessEvent{RuleName: "r", Target: target, Decision: d,
			ProcessChain: []*syncv1.Process{{Pid: 1, FilePath: proc, TeamId: "T"}, {Pid: 2, FilePath: "/sbin/launchd"}}}
	}
	_, fa, err := m.StoreEvents(n, &syncv1.EventUploadRequest{FileAccessEvents: []*syncv1.FileAccessEvent{
		ev("/Users/u/.ssh/id_ed25519", "/tmp/Evil", syncv1.FileAccessDecision_FILE_ACCESS_DECISION_DENIED),
		ev("/Users/u/Library/Cookies/c", "/Applications/Chrome", syncv1.FileAccessDecision_FILE_ACCESS_DECISION_AUDIT_ONLY),
		ev("/Users/u/100%_done", "/usr/bin/cp", syncv1.FileAccessDecision_FILE_ACCESS_DECISION_DENIED),
	}})
	require.NoError(t, err)
	require.Len(t, fa, 3, "stored events are returned for forwarding")
	require.NotZero(t, fa[0].ID)
	require.Equal(t, "/tmp/Evil", fa[0].AlertFields()["process_path"])
	require.Equal(t, "T", fa[0].AlertFields()["process_team_id"])

	for _, tt := range []struct {
		name string
		f    FileAccessFilter
		want int64
	}{
		{"all", FileAccessFilter{}, 3},
		{"target without case", FileAccessFilter{Target: "/.SSH/"}, 1},
		{"process of the chain", FileAccessFilter{Process: "launchd"}, 3},
		{"process without case", FileAccessFilter{Process: "/tmp/evil"}, 1},
		{"decision", FileAccessFilter{Decision: "denied"}, 2},
		{"LIKE characters are literal", FileAccessFilter{Target: "%_"}, 1},
		{"underscore is literal", FileAccessFilter{Target: "u_"}, 0},
		{"combined", FileAccessFilter{Target: "cookies", Decision: "AUDIT_ONLY"}, 1},
	} {
		_, total, err := m.FileAccessEvents(1, 1, 10, tt.f)
		require.NoError(t, err, tt.name)
		require.Equal(t, tt.want, total, tt.name)
	}
	for _, bad := range []FileAccessFilter{{Decision: "DENIED%"}, {Target: strings.Repeat("a", 1025)}, {Process: strings.Repeat("a", 1025)}} {
		_, _, err := m.FileAccessEvents(1, 1, 10, bad)
		require.ErrorIs(t, err, ErrInvalidEventFilter)
	}
}

func TestEventAlertFieldsSigningAndBundle(t *testing.T) {
	e := Event{Decision: "BLOCK_BINARY", BundleName: "Evil", BundleVersion: "1.0", BundlePath: "/Applications/Evil.app", BundleHash: "bh",
		SigningChain: []Cert{{SHA256: "leaf", CN: "Developer ID Application: Evil", Org: "Evil Inc", OU: "EVIL123"}, {SHA256: "root", CN: "Apple Root CA"}}}
	f := e.AlertFields()
	require.Equal(t, "leaf", f["cert_sha256"])
	require.Equal(t, "Developer ID Application: Evil", f["cert_cn"])
	require.Equal(t, "Evil Inc", f["cert_org"])
	require.Equal(t, "EVIL123", f["cert_ou"])
	require.Equal(t, "Evil", f["bundle_name"])
	require.Equal(t, "/Applications/Evil.app", f["bundle_path"])
	require.Empty(t, Event{}.AlertFields()["cert_sha256"], "unsigned")
	require.Empty(t, FileAccessEvent{}.AlertFields()["process_path"], "no chain")
}
