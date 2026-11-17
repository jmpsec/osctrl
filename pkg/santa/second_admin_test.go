package santa

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelfApprovalNeedsSecondAdmin(t *testing.T) {
	m := newTestManager(t)
	machine := strings.ToUpper(testUUID)
	shas := make([]string, 3)
	for i := range shas {
		shas[i] = fmt.Sprintf("%064x", i+1)
		require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: shas[i]}}))
	}
	ask := func(i int) Request {
		t.Helper()
		req, _, err := m.CreateRequest(1, machine, shas[i], "alice", "need it")
		require.NoError(t, err)
		return req
	}
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", RequireSecondAdmin: true}))

	req := ask(0)
	// An environment-wide rule from one's own request needs someone else.
	_, err := m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.ErrorIs(t, err, ErrSelfApproval)
	// The requesting machine only, or a denial, is not loosening the environment.
	got, err := m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice", Scope: "node"})
	require.NoError(t, err)
	require.Equal(t, RequestApproved, got.Status)
	req = ask(1)
	got, err = m.DecideRequest(1, req.ID, Decision{Approve: true, By: "bob", Scope: "env"})
	require.NoError(t, err)
	require.Equal(t, RequestApproved, got.Status)

	// Without the setting, nothing changes.
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN"}))
	req = ask(2)
	_, err = m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.NoError(t, err)
}
