package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaVotes(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	voteBody := func(sha string) string {
		b, _ := json.Marshal(SantaVoteCreate{SHA256: sha, MachineID: reqMachine})
		return string(b)
	}
	vote := func(user, sha string) *httptest.ResponseRecorder {
		return santaDo(h.SantaVoteHandler, "POST", user, voteBody(sha), p)
	}
	status := func(rr *httptest.ResponseRecorder) santa.VoteStatus {
		t.Helper()
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var st santa.VoteStatus
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &st))
		return st
	}
	get := func(user, sha string) *httptest.ResponseRecorder {
		return santaDoURL(h.SantaVoteStatusHandler, "GET", "/x?sha256="+sha, user, "", p)
	}

	// Off until an environment admin sets a threshold.
	require.Equal(t, http.StatusConflict, vote("dave", sha).Code)
	require.Zero(t, status(get("dave", sha)).GlobalThreshold)
	const cfg = `{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com","vote_local_threshold":%s,"vote_global_threshold":2}`
	put := func(user, local string) int {
		return santaDo(h.SantaConfigPutHandler, "PUT", user, strings.Replace(cfg, "%s", local, 1), p).Code
	}
	require.Equal(t, http.StatusForbidden, put("dave", "1"))
	require.Equal(t, http.StatusBadRequest, put("alice", "3"), "global below local")
	require.Equal(t, http.StatusOK, put("alice", "0"))

	other := strings.Repeat("cd", 32)
	refused := []struct {
		name string
		rr   *httptest.ResponseRecorder
		code int
	}{
		{"file never blocked", vote("dave", other), http.StatusNotFound},
		{"bad sha", vote("dave", "nope"), http.StatusBadRequest},
		{"bad sha in status", get("dave", "nope"), http.StatusBadRequest},
		{"bad body", santaDo(h.SantaVoteHandler, "POST", "dave", "{", p), http.StatusBadRequest},
		{"approval off", santaDo(h.SantaVoteHandler, "POST", "dave", voteBody(sha), map[string]string{"env": "env-b"}), http.StatusNotFound},
		{"status with approval off", santaDoURL(h.SantaVoteStatusHandler, "GET", "/x?sha256="+sha, "dave", "", map[string]string{"env": "env-b"}), http.StatusNotFound},
	}
	for _, tt := range refused {
		require.Equal(t, tt.code, tt.rr.Code, tt.name)
	}

	// One vote per account; the answer never says who voted.
	rr := vote("dave", sha)
	require.Equal(t, santa.VoteStatus{Votes: 1, GlobalThreshold: 2, Voted: true}, status(rr))
	require.NotContains(t, rr.Body.String(), "dave")
	require.EqualValues(t, 1, status(vote("dave", sha)).Votes)
	require.Equal(t, santa.VoteStatus{Votes: 1, GlobalThreshold: 2}, status(get("erin", sha)))
	rules, err := h.Santa.Rules(1)
	require.NoError(t, err)
	require.Empty(t, rules)

	// The global threshold creates one environment allow rule.
	require.Equal(t, "env", status(vote("erin", sha)).Allowed)
	require.Equal(t, "env", status(vote("erin", sha)).Allowed)
	rules, err = h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, []string{"BINARY", "ALLOWLIST", "env", sha, santa.VoteRuleCreator},
		[]string{rules[0].RuleType, rules[0].Policy, rules[0].Scope, rules[0].Identifier, rules[0].CreatedBy})

	// A block rule stops the vote.
	blockedSHA := strings.Repeat("ef", 32)
	require.NoError(t, h.Santa.AddEvents([]santa.Event{{EnvironmentID: 1, MachineID: strings.ToUpper(reqMachine), Decision: "BLOCK_UNKNOWN", FileSHA256: blockedSHA}}))
	require.NoError(t, h.Santa.CreateRule(&santa.Rule{EnvironmentID: 1, Identifier: blockedSHA, RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "tag", ScopeValue: "dev"}))
	require.Equal(t, http.StatusConflict, vote("dave", blockedSHA).Code)
	require.Zero(t, status(get("dave", blockedSHA)).Votes)

	// Admins see who voted; nobody else does.
	one := map[string]string{"env": p["env"], "sha256": sha}
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaVotesListHandler, "GET", "dave", "", one).Code)
	rr = santaDo(h.SantaVotesListHandler, "GET", "alice", "", one)
	require.Equal(t, http.StatusOK, rr.Code)
	var votes []santa.Vote
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &votes))
	require.Equal(t, []string{"dave", "erin"}, []string{votes[0].Voter, votes[1].Voter})

	// A voter withdraws their own vote; the rule stays.
	withdraw := func(user string) *httptest.ResponseRecorder {
		return santaDoURL(h.SantaVoteWithdrawHandler, "DELETE", "/x?sha256="+sha, user, "", p)
	}
	require.Equal(t, santa.VoteStatus{Votes: 1, GlobalThreshold: 2}, status(withdraw("dave")))
	require.Equal(t, http.StatusNotFound, withdraw("dave").Code)
	rules, err = h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 2, "the vote rule and the block rule")
	require.Equal(t, santa.VoteRuleCreator, rules[0].CreatedBy)

	// Deleting the rule clears the votes, so one vote does not bring it back.
	require.Equal(t, http.StatusNoContent, santaDo(h.SantaRuleDeleteHandler, "DELETE", "alice", "",
		map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(rules[0].ID), 10)}).Code)
	require.Equal(t, santa.VoteStatus{Votes: 1, GlobalThreshold: 2, Voted: true}, status(vote("dave", sha)))
	rules, err = h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1, "only the block rule")

	// A denied request stops the vote.
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "erin", reqBody(sha, "please"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	require.Equal(t, http.StatusOK, santaDo(h.SantaRequestDecideHandler, "POST", "alice", `{"decision":"deny","reason":"no"}`,
		map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}).Code)
	require.Equal(t, http.StatusConflict, vote("erin", sha).Code)
}
