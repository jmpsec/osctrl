package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
