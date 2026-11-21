package santa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRiskChecksPerEnvironment(t *testing.T) {
	sha := strings.Repeat("f6", 32)
	service := &fakeCheck{name: "virustotal", verdict: RiskClean}
	m, _ := riskManager(t, service)
	var hookCalls atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hookCalls.Add(1)
		_, _ = w.Write([]byte(`{"verdict":"flagged","detail":"env 2 says no"}`))
	}))
	defer hook.Close()
	// The test server is plain HTTP on loopback, which validation and the real
	// public client refuse: store its URL directly and use its client.
	m.Risk.PublicClient = hook.Client()
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 2, ClientMode: "LOCKDOWN", RiskChecks: RiskChecksEnv,
		RiskWebhookURL: "https://risk.example.com/check"}))
	require.NoError(t, m.DB.Model(&EnvConfig{}).Where("environment_id = ?", 2).Update("risk_webhook_url", hook.URL).Error)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 3, ClientMode: "LOCKDOWN", RiskChecks: RiskChecksNone}))

	// Environment 1 (no config) runs the service-wide check, 2 its own webhook, 3 none.
	r1, err := m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.Equal(t, RiskClean, r1.Verdict)
	require.Equal(t, "virustotal", r1.Checks[0].CheckName)
	r2, err := m.CheckRisk(context.Background(), 2, sha)
	require.NoError(t, err)
	require.Equal(t, RiskFlagged, r2.Verdict, "two environments use different checks")
	require.Len(t, r2.Checks, 1)
	require.Equal(t, "webhook@2", r2.Checks[0].CheckName)
	r3, err := m.CheckRisk(context.Background(), 3, sha)
	require.NoError(t, err)
	require.Nil(t, r3)
	on, err := m.RiskEnabled(3)
	require.NoError(t, err)
	require.False(t, on)
	require.EqualValues(t, 1, service.calls.Load(), "environment 2 does not run the service-wide check")

	// Each environment reads only its own checks from the shared cache.
	c1, err := m.cachedRisk(1, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskClean, c1[sha].Verdict)
	c2, err := m.cachedRisk(2, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskFlagged, c2[sha].Verdict)

	// New settings drop the environment's cached verdicts, and only those.
	require.NoError(t, m.ClearEnvRiskCache(2))
	c2, err = m.cachedRisk(2, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskUnchecked, c2[sha].Verdict)
	c1, err = m.cachedRisk(1, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskClean, c1[sha].Verdict)
	require.EqualValues(t, 1, hookCalls.Load())
}

func TestPublicClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := NewPublicClient(time.Second).Get(srv.URL)
	require.ErrorContains(t, err, "non-public address")
}

func TestValidateRiskSettings(t *testing.T) {
	for name, c := range map[string]EnvConfig{
		"unknown mode":      {RiskChecks: "all"},
		"http webhook":      {RiskWebhookURL: "http://risk.example.com/check"},
		"credentials":       {RiskWebhookURL: "https://u:p@risk.example.com/check"},
		"threshold too big": {RiskVirusTotalThreshold: MaxRiskThreshold + 1},
	} {
		c.ClientMode = "LOCKDOWN"
		require.Error(t, ValidateConfig(&c), name)
	}
	ok := EnvConfig{ClientMode: "LOCKDOWN", RiskChecks: RiskChecksEnv, RiskWebhookURL: "https://risk.example.com/check", RiskVirusTotalThreshold: 3}
	require.NoError(t, ValidateConfig(&ok))
}

func TestRiskOverrideForVotes(t *testing.T) {
	check := &fakeCheck{name: "virustotal", verdict: RiskFlagged}
	m, _ := riskManager(t, check)
	machine := strings.ToUpper(testUUID)
	sha := strings.Repeat("a7", 32)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", VoteGlobalThreshold: 1}))
	require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, FileSHA256: sha, Decision: "BLOCK_UNKNOWN"}}))
	_, err := m.Vote(1, machine, sha, "bob")
	require.ErrorIs(t, err, ErrRiskFlagged)

	for _, bad := range []struct{ sha, by, reason string }{{"nope", "alice", "x"}, {sha, "alice", " "}, {sha, "", "x"}} {
		_, err := m.SetRiskOverride(1, bad.sha, bad.by, bad.reason)
		require.ErrorIs(t, err, ErrInvalidRequest)
	}
	o, err := m.SetRiskOverride(1, strings.ToUpper(sha), "alice", "false positive, checked by the security team")
	require.NoError(t, err)
	require.Equal(t, "alice", o.CreatedBy)
	b, err := m.Binary(1, sha)
	require.NoError(t, err)
	require.NotNil(t, b.RiskOverride)
	require.Equal(t, RiskFlagged, b.Risk.Verdict, "the verdict is unchanged")

	calls := check.calls.Load()
	res, err := m.Vote(1, machine, sha, "bob")
	require.NoError(t, err)
	require.Len(t, res.Rules, 1)
	require.Equal(t, calls, check.calls.Load(), "an overridden file is not checked")

	found, err := m.DeleteRiskOverride(1, sha)
	require.NoError(t, err)
	require.True(t, found)
	found, err = m.DeleteRiskOverride(1, sha)
	require.NoError(t, err)
	require.False(t, found)
}
