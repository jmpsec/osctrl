package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

type stubRisk struct {
	verdict atomic.Value
	calls   atomic.Int32
}

func (s *stubRisk) Name() string { return "webhook" }
func (s *stubRisk) Check(context.Context, string) (string, string, error) {
	s.calls.Add(1)
	v, _ := s.verdict.Load().(string)
	if v == santa.RiskError {
		return "", "", fmt.Errorf("connection refused")
	}
	return v, "stub", nil
}

func TestSantaRiskApprovalAndOverride(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	stub := &stubRisk{}
	stub.verdict.Store(santa.RiskFlagged)
	h.Santa.Risk = &santa.RiskEngine{Checks: []santa.RiskCheck{stub}, TTL: time.Hour, Timeout: time.Second}

	rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "need it"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	// The new request warms the cache in the background.
	require.Eventually(t, func() bool { return stub.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.NotContains(t, rr.Body.String(), "risk", "the requester does not see verdicts")

	// The queue shows the verdict.
	rr = santaDo(h.SantaRequestsHandler, "GET", "alice", "", p)
	require.Equal(t, http.StatusOK, rr.Code)
	var queue []santa.Request
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &queue))
	require.Equal(t, santa.RiskFlagged, queue[0].Risk.Verdict)

	decide := func(body string) int {
		return santaDo(h.SantaRequestDecideHandler, "POST", "alice", body,
			map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}).Code
	}
	require.Equal(t, http.StatusConflict, decide(`{"decision":"approve","scope":"node"}`))
	require.Equal(t, http.StatusBadRequest, decide(`{"decision":"approve","scope":"node","override":true}`))
	require.Equal(t, http.StatusOK, decide(`{"decision":"approve","scope":"node","override":true,"reason":"in-house build"}`))
	logs, err := h.AuditLog.GetAll()
	require.NoError(t, err)
	var found bool
	for _, l := range logs {
		found = found || strings.Contains(l.Line, "override_risk=flagged")
	}
	require.True(t, found, "the override is audited")
}

func TestSantaBinaryRiskCheck(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	params := map[string]string{"env": p["env"], "sha256": sha}
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaBinaryRiskHandler, "POST", "alice", "", params).Code, "no check configured")

	stub := &stubRisk{}
	stub.verdict.Store(santa.RiskError)
	h.Santa.Risk = &santa.RiskEngine{Checks: []santa.RiskCheck{stub}, TTL: time.Hour, Timeout: time.Second}
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaBinaryRiskHandler, "POST", "dave", "", params).Code)
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaBinaryRiskHandler, "POST", "alice", "", map[string]string{"env": p["env"], "sha256": "x"}).Code)

	rr := santaDo(h.SantaBinaryRiskHandler, "POST", "alice", "", params)
	require.Equal(t, http.StatusOK, rr.Code)
	var risk santa.Risk
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &risk))
	require.Equal(t, santa.RiskError, risk.Verdict)

	// The binary view reads the cached verdict.
	rr = santaDo(h.SantaBinaryHandler, "GET", "alice", "", params)
	var b santa.Binary
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &b))
	require.Equal(t, santa.RiskError, b.Risk.Verdict)

	// Votes fail closed while the check is down.
	require.NoError(t, h.Santa.SaveConfig(santa.EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", VoteGlobalThreshold: 1}))
	body, _ := json.Marshal(SantaVoteCreate{SHA256: sha, MachineID: reqMachine})
	require.Equal(t, http.StatusServiceUnavailable, santaDo(h.SantaVoteHandler, "POST", "dave", string(body), p).Code)
}
