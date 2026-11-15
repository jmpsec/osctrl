package santa

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateConfigVoteThresholds(t *testing.T) {
	const url = "https://osctrl.example.com"
	tests := []struct {
		name          string
		url           string
		local, global uint32
		ok            bool
	}{
		{"off", "", 0, 0, true},
		{"local only", url, 2, 0, true},
		{"global only", url, 0, 5, true},
		{"both", url, 2, 5, true},
		{"equal", url, 3, 3, true},
		{"global below local", url, 5, 2, false},
		{"without the approval URL", "", 2, 0, false},
		{"too high", url, 0, MaxVoteThreshold + 1, false},
	}
	for _, tt := range tests {
		c := EnvConfig{ClientMode: "LOCKDOWN", ApprovalURL: tt.url, VoteLocalThreshold: tt.local, VoteGlobalThreshold: tt.global}
		err := ValidateConfig(&c)
		require.Equal(t, tt.ok, err == nil, tt.name)
	}

	m := newTestManager(t)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: url, VoteLocalThreshold: 2, VoteGlobalThreshold: 4}))
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: url, VoteLocalThreshold: 3}))
	got, err := m.Config(1)
	require.NoError(t, err)
	require.EqualValues(t, 3, got.VoteLocalThreshold)
	require.Zero(t, got.VoteGlobalThreshold)
}

func TestVote(t *testing.T) {
	m := newTestManager(t)
	sha := strings.Repeat("a1", 32)
	machine := func(i int) string { return fmt.Sprintf("00000000-0000-0000-0000-%012d", i) }
	blocked := func(env uint, i int, sha, decision string, ev Event) {
		t.Helper()
		ev.EnvironmentID, ev.MachineID, ev.FileSHA256, ev.Decision = env, machine(i), sha, decision
		require.NoError(t, m.AddEvents([]Event{ev}))
	}
	for i := 1; i <= 5; i++ {
		blocked(1, i, sha, "BLOCK_UNKNOWN", Event{})
	}
	vote := func(i int) VoteResult {
		t.Helper()
		res, err := m.Vote(1, machine(i), sha, fmt.Sprintf("user%d", i))
		require.NoError(t, err)
		return res
	}

	_, err := m.Vote(1, machine(1), sha, "user1")
	require.ErrorIs(t, err, ErrVotingOff)
	require.NoError(t, m.SaveConfig(EnvConfig{
		EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", VoteLocalThreshold: 2, VoteGlobalThreshold: 4,
	}))

	for name, call := range map[string]func() error{
		"bad machine":       func() error { _, err := m.Vote(1, "nope", sha, "user1"); return err },
		"bad sha":           func() error { _, err := m.Vote(1, machine(1), "nope", "user1"); return err },
		"no voter":          func() error { _, err := m.Vote(1, machine(1), sha, ""); return err },
		"bad status sha":    func() error { _, err := m.VoteStatus(1, "nope", "user1"); return err },
		"unblocked machine": func() error { _, err := m.Vote(1, machine(9), sha, "user9"); return err },
	} {
		err := call()
		if name == "unblocked machine" {
			require.ErrorIs(t, err, ErrNoBlockedEvent, name)
		} else {
			require.ErrorIs(t, err, ErrInvalidRequest, name)
		}
	}

	// Below the local threshold: counted, nothing allowed.
	res := vote(1)
	require.True(t, res.Counted)
	require.Equal(t, VoteStatus{Votes: 1, LocalThreshold: 2, GlobalThreshold: 4, Voted: true}, res.VoteStatus)
	require.Empty(t, res.Rules)
	// One vote per user per file, from any machine.
	blocked(1, 2, sha, "BLOCK_UNKNOWN", Event{})
	again, err := m.Vote(1, machine(2), sha, "user1")
	require.NoError(t, err)
	require.False(t, again.Counted)
	require.EqualValues(t, 1, again.Votes)

	// The local threshold allows every voter's machine so far.
	res = vote(2)
	require.Equal(t, "node", res.Allowed)
	require.Len(t, res.Rules, 2)
	for _, r := range res.Rules {
		require.Equal(t, []string{"BINARY", "ALLOWLIST", "node", sha, VoteRuleCreator}, []string{r.RuleType, r.Policy, r.Scope, r.Identifier, r.CreatedBy})
	}
	require.ElementsMatch(t, []string{machine(1), machine(2)}, []string{res.Rules[0].ScopeValue, res.Rules[1].ScopeValue})
	// Someone who has not voted is not allowed yet.
	st, err := m.VoteStatus(1, strings.ToUpper(sha), "user5")
	require.NoError(t, err)
	require.Equal(t, VoteStatus{Votes: 2, LocalThreshold: 2, GlobalThreshold: 4}, st)

	// Past it, each vote allows the voter's own machine.
	res = vote(3)
	require.Len(t, res.Rules, 1)
	require.Equal(t, machine(3), res.Rules[0].ScopeValue)

	// The global threshold creates one environment rule, once.
	res = vote(4)
	require.Equal(t, "env", res.Allowed)
	require.Len(t, res.Rules, 1)
	require.Equal(t, []string{"env", ""}, []string{res.Rules[0].Scope, res.Rules[0].ScopeValue})
	res = vote(5)
	require.Equal(t, "env", res.Allowed)
	require.Empty(t, res.Rules)
	rules, err := m.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 4)

	// Votes do not cross environments.
	st, err = m.VoteStatus(2, sha, "user1")
	require.NoError(t, err)
	require.Zero(t, st.Votes)
}

func TestVoteKnownBad(t *testing.T) {
	const team, signing, cdhash = "ABCDE12345", "ABCDE12345:com.example.tool", "0123456789abcdef0123456789abcdef01234567"
	shas := make([]string, 8)
	for i := range shas {
		shas[i] = strings.Repeat(fmt.Sprintf("%02x", i+1), 32)
	}
	tests := []struct {
		name     string
		decision string
		rule     *Rule
		bad      bool
	}{
		{"unknown file", "BLOCK_UNKNOWN", nil, false},
		{"allow rule elsewhere", "BLOCK_UNKNOWN", &Rule{RuleType: "BINARY", Policy: "ALLOWLIST", Scope: "tag", ScopeValue: "dev"}, false},
		{"blocked by a rule on the machine", "BLOCK_BINARY", nil, true},
		{"block rule for another tag", "BLOCK_UNKNOWN", &Rule{RuleType: "BINARY", Policy: "SILENT_BLOCKLIST", Scope: "tag", ScopeValue: "dev"}, true},
		{"team ID block rule", "BLOCK_UNKNOWN", &Rule{RuleType: "TEAMID", Identifier: team, Policy: "BLOCKLIST", Scope: "env"}, true},
		{"signing ID CEL rule", "BLOCK_UNKNOWN", &Rule{RuleType: "SIGNINGID", Identifier: signing, Policy: "CEL", CELExpr: "true", Scope: "env"}, true},
		{"CDHash block rule", "BLOCK_UNKNOWN", &Rule{RuleType: "CDHASH", Identifier: cdhash, Policy: "BLOCKLIST", Scope: "env"}, true},
		{"leaf certificate block rule", "BLOCK_UNKNOWN", &Rule{RuleType: "CERTIFICATE", Identifier: strings.Repeat("c3", 32), Policy: "BLOCKLIST", Scope: "env"}, true},
	}
	machine := strings.ToUpper(testUUID)
	for i, tt := range tests {
		// One environment per case, so rules do not leak between them.
		m := newTestManager(t)
		require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", VoteGlobalThreshold: 1}))
		require.NoError(t, m.AddEvents([]Event{{
			EnvironmentID: 1, MachineID: machine, FileSHA256: shas[i], Decision: tt.decision, TeamID: team, SigningID: signing, CDHash: cdhash,
			SigningChain: []Cert{{SHA256: strings.Repeat("C3", 32)}},
		}}))
		if tt.rule != nil {
			r := *tt.rule
			r.EnvironmentID = 1
			if r.Identifier == "" {
				r.Identifier = shas[i]
			}
			require.NoError(t, m.CreateRule(&r), tt.name)
		}
		res, err := m.Vote(1, machine, shas[i], "bob")
		if tt.bad {
			require.ErrorIs(t, err, ErrKnownBad, tt.name)
			st, err := m.VoteStatus(1, shas[i], "bob")
			require.NoError(t, err)
			require.Zero(t, st.Votes, tt.name)
			continue
		}
		require.NoError(t, err, tt.name)
		require.Len(t, res.Rules, 1, tt.name)
		require.Equal(t, "env", res.Rules[0].Scope, tt.name)
	}
}
