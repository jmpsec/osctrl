package santa

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVoteManagement(t *testing.T) {
	m := newTestManager(t)
	now := testNow()
	m.now = func() time.Time { return now }
	sha := strings.Repeat("b2", 32)
	machine := func(i int) string { return fmt.Sprintf("00000000-0000-0000-0000-%012d", i) }
	for i := 1; i <= 4; i++ {
		require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine(i), FileSHA256: sha, Decision: "BLOCK_UNKNOWN"}}))
	}
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com",
		VoteGlobalThreshold: 2, VoteExpiryDays: 30}))
	vote := func(i int) (VoteResult, error) { return m.Vote(1, machine(i), sha, fmt.Sprintf("user%d", i)) }

	// A withdrawn vote no longer counts, and withdrawing twice finds nothing.
	_, err := vote(1)
	require.NoError(t, err)
	gone, err := m.WithdrawVote(1, strings.ToUpper(sha), "user1")
	require.NoError(t, err)
	require.True(t, gone)
	gone, err = m.WithdrawVote(1, sha, "user1")
	require.NoError(t, err)
	require.False(t, gone)

	// Two votes allow it environment-wide.
	_, err = vote(1)
	require.NoError(t, err)
	res, err := vote(2)
	require.NoError(t, err)
	require.Len(t, res.Rules, 1)
	votes, err := m.Votes(1, sha)
	require.NoError(t, err)
	require.Len(t, votes, 2)
	require.Equal(t, []string{"user1", "user2"}, []string{votes[0].Voter, votes[1].Voter})
	require.Equal(t, machine(2), votes[1].MachineID)

	// Deleting the vote-created rule clears the votes: one new vote does not recreate it.
	cleared, err := m.DeleteRule(1, res.Rules[0].ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, cleared)
	res, err = vote(3)
	require.NoError(t, err)
	require.Empty(t, res.Rules)
	require.EqualValues(t, 1, res.Votes)

	// Deleting a rule an admin made leaves the votes.
	admin := Rule{EnvironmentID: 1, Identifier: sha, RuleType: "BINARY", Policy: "ALLOWLIST", Scope: "node", ScopeValue: machine(9), CreatedBy: "alice"}
	require.NoError(t, m.CreateRule(&admin))
	cleared, err = m.DeleteRule(1, admin.ID)
	require.NoError(t, err)
	require.Zero(t, cleared)

	// Votes expire with the environment's setting.
	pruned, err := m.PruneVotes(now.Add(29 * 24 * time.Hour))
	require.NoError(t, err)
	require.Zero(t, pruned)
	pruned, err = m.PruneVotes(now.Add(31 * 24 * time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 1, pruned)

	// A denied request stops voting for the file.
	req, _, err := m.CreateRequest(1, machine(4), sha, "user4", "please")
	require.NoError(t, err)
	_, err = m.DecideRequest(1, req.ID, Decision{By: "alice", Reason: "no"})
	require.NoError(t, err)
	_, err = vote(4)
	require.ErrorIs(t, err, ErrVoteDenied)

	_, err = m.Votes(1, "nope")
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, err = m.WithdrawVote(1, "nope", "user1")
	require.ErrorIs(t, err, ErrInvalidRequest)

	c := EnvConfig{ClientMode: "LOCKDOWN", VoteExpiryDays: MaxVoteExpiryDays + 1}
	require.Error(t, ValidateConfig(&c))
}
