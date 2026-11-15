package santa

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestValidateConfigApprovalURL(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{" https://osctrl.example.com/ ", "https://osctrl.example.com", true},
		{"https://osctrl.example.com/ui", "https://osctrl.example.com/ui", true},
		{"http://osctrl.example.com", "", false},
		{"https://", "", false},
		{"https://user@osctrl.example.com", "", false},
		{"https://osctrl.example.com/?x=1", "", false},
		{"https://osctrl.example.com/#frag", "", false},
		{"https://osctrl.example.com/%username%", "", false},
		{"javascript:alert(1)", "", false},
		{"https://osctrl.example.com/" + strings.Repeat("a", 250), "", false},
	}
	for _, tt := range tests {
		c := EnvConfig{ClientMode: "MONITOR", ApprovalURL: tt.in}
		err := ValidateConfig(&c)
		if !tt.ok {
			require.Error(t, err, tt.in)
			continue
		}
		require.NoError(t, err, tt.in)
		require.Equal(t, tt.want, c.ApprovalURL)
	}
}

func TestPreflightEventDetailURL(t *testing.T) {
	m := newTestManager(t)
	n := testNode()
	n.EnvUUID = "env uuid"
	resp := mustPreflight(t, m, n, false)
	require.False(t, resp.HasEventDetailUrl(), "off by default")

	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com/"}))
	resp = mustPreflight(t, m, n, false)
	require.Equal(t, "https://osctrl.example.com/santa/request/env%20uuid?sha256=%file_sha%&machine_id=%machine_id%", resp.GetEventDetailUrl())
	require.Equal(t, "Request approval", resp.GetEventDetailText())

	// Saving the config without the URL turns the link off again.
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN"}))
	require.False(t, mustPreflight(t, m, n, false).HasEventDetailUrl())
}

func TestCreateRequest(t *testing.T) {
	m := newTestManager(t)
	sha := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	machine := strings.ToUpper(testUUID)
	require.NoError(t, m.AddEvents([]Event{
		{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_UNKNOWN", FileSHA256: sha, FileName: "tool", FilePath: "/tmp", SigningID: "sid"},
		{EnvironmentID: 1, MachineID: machine, Decision: "ALLOW_BINARY", FileSHA256: other},
		{EnvironmentID: 2, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: other},
	}))

	bad := []struct{ name, machine, sha, who, why string }{
		{"machine not a uuid", "M-1", sha, "bob", "need it"},
		{"short hash", machine, "abcd", "bob", "need it"},
		{"blank justification", machine, sha, "bob", "  "},
		{"long justification", machine, sha, "bob", strings.Repeat("é", MaxJustification+1)},
		{"no requester", machine, sha, "", "need it"},
	}
	for _, tt := range bad {
		_, _, err := m.CreateRequest(1, tt.machine, tt.sha, tt.who, tt.why)
		require.ErrorIs(t, err, ErrInvalidRequest, tt.name)
	}
	// Allowed here, blocked only in another environment, never seen: no request.
	for _, s := range []string{other, strings.Repeat("ef", 32)} {
		_, _, err := m.CreateRequest(1, machine, s, "bob", "need it")
		require.ErrorIs(t, err, ErrNoBlockedEvent)
	}

	req, created, err := m.CreateRequest(1, strings.ToLower(machine), strings.ToUpper(sha), "bob", " need it ")
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, RequestPending, req.Status)
	require.Equal(t, "need it", req.Justification)
	require.Equal(t, "tool", req.FileName)
	require.Equal(t, "sid", req.SigningID)
	require.NotZero(t, req.EventID)
	// The limit counts characters, not bytes.
	_, _, err = m.CreateRequest(1, machine, sha, "bob", strings.Repeat("é", MaxJustification))
	require.NoError(t, err)

	// The same file and machine merge into the pending request, whoever asks.
	for _, who := range []string{"bob", "eve"} {
		again, created, err := m.CreateRequest(1, machine, sha, who, "me too")
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, req.ID, again.ID)
		require.Equal(t, "need it", again.Justification)
	}
	all, err := m.Requests(1, "", "")
	require.NoError(t, err)
	require.Len(t, all, 1)
	mine, err := m.Requests(1, "", "eve")
	require.NoError(t, err)
	require.Empty(t, mine)
	inOther, err := m.Requests(2, "", "")
	require.NoError(t, err)
	require.Empty(t, inOther)

	// Expiry only touches old pending requests; a decided file can be asked for again.
	n, err := m.ExpireRequests(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = m.ExpireRequests(time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	expired, err := m.Requests(1, RequestExpired, "")
	require.NoError(t, err)
	require.Len(t, expired, 1)
	_, created, err = m.CreateRequest(1, machine, sha, "eve", "again")
	require.NoError(t, err)
	require.True(t, created)
}

func TestCreateRequestPendingCap(t *testing.T) {
	m := newTestManager(t)
	machine := strings.ToUpper(testUUID)
	evs := make([]Event, MaxPendingRequests+1)
	for i := range evs {
		evs[i] = Event{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: fmt.Sprintf("%064x", i)}
	}
	require.NoError(t, m.AddEvents(evs))
	for i := 0; i < MaxPendingRequests; i++ {
		_, _, err := m.CreateRequest(1, machine, evs[i].FileSHA256, "bob", "need it")
		require.NoError(t, err)
	}
	_, _, err := m.CreateRequest(1, machine, evs[MaxPendingRequests].FileSHA256, "bob", "need it")
	require.ErrorIs(t, err, ErrTooManyRequests)
	// The cap is per requester.
	_, _, err = m.CreateRequest(1, machine, evs[MaxPendingRequests].FileSHA256, "eve", "need it")
	require.NoError(t, err)
}

func TestDecideRequest(t *testing.T) {
	m := newTestManager(t)
	machine := strings.ToUpper(testUUID)
	shas := make([]string, 6)
	evs := make([]Event, len(shas))
	for i := range shas {
		shas[i] = fmt.Sprintf("%064x", i+1)
		evs[i] = Event{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_BINARY", FileSHA256: shas[i]}
	}
	require.NoError(t, m.AddEvents(evs))
	ask := func(i int) Request {
		t.Helper()
		req, created, err := m.CreateRequest(1, machine, shas[i], "bob", "need it")
		require.NoError(t, err)
		require.True(t, created)
		return req
	}
	rulesFor := func(sha string) []Rule {
		t.Helper()
		var rs []Rule
		require.NoError(t, m.DB.Where("identifier = ?", sha).Find(&rs).Error)
		return rs
	}

	req := ask(0)
	bad := []struct {
		name string
		d    Decision
	}{
		{"no approver", Decision{Approve: true, Scope: "env"}},
		{"deny without reason", Decision{By: "alice", Reason: "  "}},
		{"long reason", Decision{By: "alice", Reason: strings.Repeat("é", MaxJustification+1)}},
	}
	for _, tt := range bad {
		_, err := m.DecideRequest(1, req.ID, tt.d)
		require.ErrorIs(t, err, ErrInvalidRequest, tt.name)
	}
	for _, d := range []Decision{{Approve: true, By: "alice", Scope: "everywhere"}, {Approve: true, By: "alice", Scope: "tag"}} {
		_, err := m.DecideRequest(1, req.ID, d)
		require.ErrorIs(t, err, ErrInvalidRule)
	}
	// Another environment cannot decide it, and nothing above changed it.
	_, err := m.DecideRequest(2, req.ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	require.Empty(t, rulesFor(shas[0]))

	// Approving for the machine: one node rule the machine gets on its next sync.
	got, err := m.DecideRequest(1, req.ID, Decision{Approve: true, By: "alice", Scope: "node", ScopeValue: "ignored"})
	require.NoError(t, err)
	require.Equal(t, RequestApproved, got.Status)
	require.Equal(t, "alice", got.DecidedBy)
	require.NotNil(t, got.DecidedAt)
	rules := rulesFor(shas[0])
	require.Len(t, rules, 1)
	require.Equal(t, got.RuleID, rules[0].ID)
	require.Equal(t, Rule{
		ID: rules[0].ID, CreatedAt: rules[0].CreatedAt, UpdatedAt: rules[0].UpdatedAt, EnvironmentID: 1,
		Identifier: shas[0], RuleType: "BINARY", Policy: "ALLOWLIST", Scope: "node", ScopeValue: machine, CreatedBy: "alice",
	}, rules[0])
	eff, err := m.EffectiveRules(1, testUUID, nil)
	require.NoError(t, err)
	require.Len(t, eff, 1)
	other, err := m.EffectiveRules(1, "11111111-2222-3333-4444-555555555555", nil)
	require.NoError(t, err)
	require.Empty(t, other)

	// A decided request cannot be decided again, either way.
	for _, d := range []Decision{{Approve: true, By: "carol", Scope: "env"}, {By: "carol", Reason: "no"}} {
		_, err = m.DecideRequest(1, req.ID, d)
		require.ErrorIs(t, err, ErrRequestNotPending)
	}
	require.Len(t, rulesFor(shas[0]), 1)
	stored, err := m.Requests(1, RequestApproved, "")
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, "alice", stored[0].DecidedBy)

	// Tag and environment scopes.
	got, err = m.DecideRequest(1, ask(1).ID, Decision{Approve: true, By: "alice", Scope: "tag", ScopeValue: "dev"})
	require.NoError(t, err)
	require.Equal(t, "dev", rulesFor(shas[1])[0].ScopeValue)
	got, err = m.DecideRequest(1, ask(2).ID, Decision{Approve: true, By: "alice", Scope: "env", ScopeValue: "ignored"})
	require.NoError(t, err)
	require.Equal(t, "", rulesFor(shas[2])[0].ScopeValue)
	require.NotZero(t, got.RuleID)

	// An allow rule already there is reused, not duplicated.
	allow := Rule{EnvironmentID: 1, Identifier: shas[3], RuleType: "BINARY", Policy: "ALLOWLIST_COMPILER", Scope: "env"}
	require.NoError(t, m.CreateRule(&allow))
	got, err = m.DecideRequest(1, ask(3).ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.NoError(t, err)
	require.Equal(t, allow.ID, got.RuleID)
	require.Len(t, rulesFor(shas[3]), 1)

	// A block rule in the same scope is not overridden; the request stays pending.
	block := Rule{EnvironmentID: 1, Identifier: shas[4], RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "env"}
	require.NoError(t, m.CreateRule(&block))
	blocked := ask(4)
	_, err = m.DecideRequest(1, blocked.ID, Decision{Approve: true, By: "alice", Scope: "env"})
	require.ErrorIs(t, err, ErrRuleConflict)
	pending, err := m.Requests(1, RequestPending, "")
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, blocked.ID, pending[0].ID)

	// Denying records the reason and creates no rule.
	got, err = m.DecideRequest(1, ask(5).ID, Decision{By: "alice", Reason: " not company software ", Scope: "env"})
	require.NoError(t, err)
	require.Equal(t, RequestDenied, got.Status)
	require.Equal(t, "not company software", got.Reason)
	require.Zero(t, got.RuleID)
	require.Empty(t, rulesFor(shas[5]))
}
