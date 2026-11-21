package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestSantaRiskSettings(t *testing.T) {
	h, _, envA, _ := setupSantaHandlers(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	p := map[string]string{"env": envA.Name}
	put := func(user, body string) (int, string) {
		rr := santaDo(h.SantaConfigPutHandler, "PUT", user, body, p)
		return rr.Code, rr.Body.String()
	}
	const base = `{"client_mode":"LOCKDOWN"`

	code, _ := put("alice", base+`,"risk_checks":"env","risk_virustotal_key":"vt-secret"}`)
	require.Equal(t, http.StatusForbidden, code, "an environment admin cannot change the risk checks")
	code, _ = put("root", base+`,"risk_checks":"env","risk_webhook_url":"http://10.0.0.1/check"}`)
	require.Equal(t, http.StatusBadRequest, code)

	code, body := put("root", base+`,"risk_checks":"env","risk_virustotal_key":"vt-secret","risk_virustotal_threshold":3,`+
		`"risk_webhook_url":"https://risk.example.com/check?token=hook-secret","risk_webhook_secret":"hmac-secret"}`)
	require.Equal(t, http.StatusOK, code, body)
	for _, secret := range []string{"vt-secret", "hook-secret", "hmac-secret"} {
		require.NotContains(t, body, secret, "secrets are never returned")
	}
	var res SantaConfigResponse
	require.NoError(t, json.Unmarshal([]byte(body), &res))
	require.Equal(t, santa.RiskChecksEnv, res.RiskChecks)
	require.True(t, res.RiskVirusTotalKeySet && res.RiskWebhookURLSet && res.RiskWebhookSecretSet)
	require.EqualValues(t, 3, res.RiskVirusTotalThreshold)
	require.NotNil(t, res.RiskServiceChecks)

	// An admin saving other settings echoes the risk fields without secrets: nothing changes.
	code, body = put("alice", base+`,"batch_size":10,"risk_checks":"env","risk_virustotal_threshold":3}`)
	require.Equal(t, http.StatusOK, code, body)
	cfg, err := h.Santa.Config(envA.ID)
	require.NoError(t, err)
	require.Equal(t, "vt-secret", cfg.RiskVirusTotalKey)
	require.Equal(t, "hmac-secret", cfg.RiskWebhookSecret)

	code, _ = put("root", base+`,"risk_checks":"env","risk_virustotal_threshold":3,"risk_clear_webhook":true}`)
	require.Equal(t, http.StatusOK, code)
	cfg, err = h.Santa.Config(envA.ID)
	require.NoError(t, err)
	require.Empty(t, cfg.RiskWebhookURL)
	require.Empty(t, cfg.RiskWebhookSecret)
	require.Equal(t, "vt-secret", cfg.RiskVirusTotalKey)

	logs, err := h.AuditLog.GetAll()
	require.NoError(t, err)
	var audited bool
	for _, l := range logs {
		audited = audited || strings.Contains(l.Line, "update config risk_checks=env")
		require.NotContains(t, l.Line, "vt-secret")
	}
	require.True(t, audited)

	// A held change keeps its body for the second admin: secrets cannot ride along.
	require.NoError(t, h.Santa.SaveConfig(santa.EnvConfig{EnvironmentID: envA.ID, ClientMode: "LOCKDOWN", RequireSecondAdmin: true,
		RiskChecks: santa.RiskChecksEnv, RiskVirusTotalKey: "vt-secret"}))
	code, body = put("root", `{"client_mode":"MONITOR","require_second_admin":true,"risk_checks":"env","risk_virustotal_key":"new-secret"}`)
	require.Equal(t, http.StatusBadRequest, code, body)
	require.Contains(t, body, "on their own")
	code, body = put("root", base+`,"require_second_admin":true,"risk_checks":"env","risk_virustotal_key":"new-secret"}`)
	require.Equal(t, http.StatusOK, code, "risk changes alone are not held: superuser is the guard: %s", body)
}

func TestSantaRiskOverrideRoutes(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	params := map[string]string{"env": p["env"], "sha256": strings.ToUpper(sha)}
	put := func(user, body string) int {
		return santaDo(h.SantaRiskOverrideHandler, "PUT", user, body, params).Code
	}
	require.Equal(t, http.StatusForbidden, put("dave", `{"reason":"x"}`))
	require.Equal(t, http.StatusBadRequest, put("alice", `{"reason":" "}`))
	require.Equal(t, http.StatusOK, put("alice", `{"reason":"false positive\nconfirmed"}`))

	rr := santaDo(h.SantaBinaryHandler, "GET", "alice", "", params)
	var b santa.Binary
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &b))
	require.NotNil(t, b.RiskOverride)
	require.Equal(t, "alice", b.RiskOverride.CreatedBy)

	logs, err := h.AuditLog.GetAll()
	require.NoError(t, err)
	var audited bool
	for _, l := range logs {
		audited = audited || strings.Contains(l.Line, "risk override for votes sha256="+sha+" reason=false positive confirmed")
	}
	require.True(t, audited, "the override and its reason are audited on one line")

	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRiskOverrideDeleteHandler, "DELETE", "dave", "", params).Code)
	require.Equal(t, http.StatusNoContent, santaDo(h.SantaRiskOverrideDeleteHandler, "DELETE", "alice", "", params).Code)
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaRiskOverrideDeleteHandler, "DELETE", "alice", "", params).Code)
}
