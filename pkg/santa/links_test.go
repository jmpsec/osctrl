package santa

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateConfigNotifyChannels(t *testing.T) {
	c := EnvConfig{ClientMode: "MONITOR", ApprovalURL: "https://osctrl.example.com", NotifyChannels: []uint{3, 1, 3}}
	require.NoError(t, ValidateConfig(&c))
	require.Equal(t, []uint{1, 3}, c.NotifyChannels)

	c = EnvConfig{ClientMode: "MONITOR", NotifyChannels: []uint{1}}
	require.Error(t, ValidateConfig(&c), "channels without the approval URL")

	many := make([]uint, MaxNotifyChannels+1)
	for i := range many {
		many[i] = uint(i + 1)
	}
	c = EnvConfig{ClientMode: "MONITOR", ApprovalURL: "https://osctrl.example.com", NotifyChannels: many}
	require.Error(t, ValidateConfig(&c))

	m := newTestManager(t)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR", ApprovalURL: "https://osctrl.example.com", NotifyChannels: []uint{2}}))
	got, err := m.Config(1)
	require.NoError(t, err)
	require.Equal(t, []uint{2}, got.NotifyChannels)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "MONITOR"}))
	got, err = m.Config(1)
	require.NoError(t, err)
	require.Empty(t, got.NotifyChannels)
}

func TestDecideByLink(t *testing.T) {
	m := newTestManager(t)
	now := testNow()
	m.now = func() time.Time { return now }
	machine := strings.ToUpper(testUUID)
	shas := []string{strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)}
	for _, s := range shas {
		require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: s}}))
	}
	ask := func(i int) (Request, string, string) {
		t.Helper()
		req, _, err := m.CreateRequest(1, machine, shas[i], "bob", "need it")
		require.NoError(t, err)
		approve, deny, err := m.NewRequestLinks(req)
		require.NoError(t, err)
		require.NotEqual(t, approve, deny)
		return req, approve, deny
	}
	approveNode := Decision{Approve: true, By: "alice", Scope: "node"}
	denyIt := Decision{By: "alice", Reason: "no"}

	req, approve, deny := ask(0)
	// Only token hashes are stored.
	var stored []RequestLink
	require.NoError(t, m.DB.Find(&stored).Error)
	require.Len(t, stored, 2)
	for _, l := range stored {
		require.NotContains(t, []string{approve, deny}, l.TokenHash)
		require.Equal(t, now.Add(LinkTTL).Unix(), l.ExpiresAt.Unix())
	}

	refused := []struct {
		name  string
		env   uint
		token string
		d     Decision
	}{
		{"unknown token", 1, "nope", approveNode},
		{"empty token", 1, "", approveNode},
		{"another environment", 2, approve, approveNode},
		{"approve link used to deny", 1, approve, denyIt},
		{"deny link used to approve", 1, deny, approveNode},
	}
	for _, tt := range refused {
		_, err := m.DecideByLink(tt.env, tt.token, tt.d)
		require.ErrorIs(t, err, ErrLinkInvalid, tt.name)
	}
	// A decision that fails does not consume the link.
	_, err := m.DecideByLink(1, approve, Decision{Approve: true, By: "alice", Scope: "tag"})
	require.ErrorIs(t, err, ErrInvalidRule)
	_, err = m.DecideByLink(1, deny, Decision{By: "alice"})
	require.ErrorIs(t, err, ErrInvalidRequest)

	got, err := m.DecideByLink(1, approve, approveNode)
	require.NoError(t, err)
	require.Equal(t, req.ID, got.ID)
	require.Equal(t, RequestApproved, got.Status)
	rules, err := m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// Replay fails, and the sibling link dies with the request.
	_, err = m.DecideByLink(1, approve, approveNode)
	require.ErrorIs(t, err, ErrLinkInvalid)
	_, err = m.DecideByLink(1, deny, denyIt)
	require.ErrorIs(t, err, ErrRequestNotPending)
	rules, err = m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.NoError(t, m.DB.Where("used_at IS NOT NULL").Find(&stored).Error)
	require.Len(t, stored, 1)
	require.Equal(t, "alice", stored[0].UsedBy)

	// The deny link works for its request.
	req, _, deny = ask(1)
	got, err = m.DecideByLink(1, deny, denyIt)
	require.NoError(t, err)
	require.Equal(t, RequestDenied, got.Status)
	require.Equal(t, req.ID, got.ID)

	// Expired links fail closed, at the exact expiry too, and are pruned.
	req, approve, _ = ask(2)
	now = now.Add(LinkTTL)
	_, err = m.DecideByLink(1, approve, approveNode)
	require.ErrorIs(t, err, ErrLinkInvalid)
	pending, err := m.Request(1, req.ID)
	require.NoError(t, err)
	require.Equal(t, RequestPending, pending.Status)
	n, err := m.PruneLinks(now.Add(time.Second))
	require.NoError(t, err)
	require.EqualValues(t, 6, n)
}

func TestDecisionLinkAndNotice(t *testing.T) {
	require.Equal(t, "https://osctrl.example.com/santa/decide/env%20uuid?request=7&action=approve#tok",
		DecisionLink("https://osctrl.example.com", "env uuid", 7, true, "tok"))
	require.Contains(t, DecisionLink("https://o.example.com", "e", 7, false, "tok"), "action=deny#tok")

	notice := RequestNotice(Request{
		Requester: "bob", FileName: "tool\r\nApprove: https://evil.example", FileSHA256: "abc", MachineID: "M",
		Justification: "line one\n\nDeny: https://evil.example",
	})
	require.NotContains(t, notice, "\n")
	require.NotContains(t, notice, "\r")
	require.Contains(t, notice, "bob asks to allow tool Approve: https://evil.example (sha256 abc) on machine M.")
	require.Contains(t, RequestNotice(Request{FileSHA256: "abc"}), "allow abc ")
}
