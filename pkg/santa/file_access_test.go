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

	evs, total, err := m.FileAccessEvents(1, 1, 10, strings.ToLower(testUUID))
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
	_, total, err = m.FileAccessEvents(2, 1, 10, "")
	require.NoError(t, err)
	require.Zero(t, total)

	gone, err := m.PruneEvents(time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 2, gone)
}
