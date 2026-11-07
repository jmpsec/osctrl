package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/vulns"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAlertsHandler(t *testing.T) *HandlersApi {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&alerts.AlertRule{}, &alerts.AlertChannel{}, &alerts.AlertHistory{}))
	userManager := users.CreateUserManager(db)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice", Admin: true}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"})) // non-admin
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", false)
	require.NoError(t, err)
	h := CreateHandlersApi(
		WithUsers(userManager),
		WithAuditLog(auditLog),
		WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		WithAlerts(&alerts.Manager{DB: db}),
		WithServiceCommands(servicecommands.NewManager(db)),
	)
	return h
}

func alertsCtx(user string) context.Context {
	return context.WithValue(context.Background(), ContextKey(contextAPI), ContextValue{ctxUser: user})
}

// call executes a handler with the admin context and a JSON body.
func call(t *testing.T, h http.HandlerFunc, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return callPathValue(t, h, method, path, body, nil)
}

// callWithID executes a handler with the admin context and the {id}
// path variable set.
func callWithID(t *testing.T, h http.HandlerFunc, method, path string, id uint, body any) *httptest.ResponseRecorder {
	t.Helper()
	return callPathValue(t, h, method, path, body, map[string]string{"id": strconv.FormatUint(uint64(id), 10)})
}

func callPathValue(t *testing.T, h http.HandlerFunc, method, path string, body any, vars map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader).WithContext(alertsCtx("alice"))
	for k, v := range vars {
		req.SetPathValue(k, v)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func callAs(t *testing.T, h http.HandlerFunc, user, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil).WithContext(alertsCtx(user))
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func ruleBody() map[string]any {
	return map[string]any{
		"name": "sudoers-write", "environment_id": 0, "source": "result_log",
		"match_type": "substring", "match_value": "/etc/sudoers",
		"cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	}
}

func TestAlertsRejectNonAdmin(t *testing.T) {
	h := setupAlertsHandler(t)
	require.Equal(t, http.StatusForbidden, callAs(t, h.AlertRulesListHandler, "bob", http.MethodGet, "/api/v1/alerts/rules").Code)
	require.Equal(t, http.StatusForbidden, callAs(t, h.AlertChannelsListHandler, "bob", http.MethodGet, "/api/v1/alerts/channels").Code)
}

func TestAlertsDisabledReturns503(t *testing.T) {
	h := setupAlertsHandler(t)
	h.Alerts = nil
	require.Equal(t, http.StatusServiceUnavailable, callAs(t, h.AlertRulesListHandler, "alice", http.MethodGet, "/api/v1/alerts/rules").Code)
}

func TestAlertRuleCRUDRoundTrip(t *testing.T) {
	h := setupAlertsHandler(t)

	// create
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", ruleBody())
	require.Equal(t, http.StatusCreated, rr.Code)
	var created alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.Equal(t, "sudoers-write", created.Name)
	require.Equal(t, []uint{1}, created.ChannelIDs)

	// duplicate → 409
	rr = call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", ruleBody())
	require.Equal(t, http.StatusConflict, rr.Code)

	// list
	rr = call(t, h.AlertRulesListHandler, http.MethodGet, "/api/v1/alerts/rules", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var list []alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)

	// get
	rr = callWithID(t, h.AlertRuleGetHandler, http.MethodGet, "/api/v1/alerts/rules/{id}", created.ID, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	// update
	rr = callWithID(t, h.AlertRulesUpdateHandler, http.MethodPut, "/api/v1/alerts/rules/{id}", created.ID, map[string]any{
		"name": "sudoers-write", "environment_id": 0, "source": "result_log",
		"match_type": "substring", "match_value": "/etc/sudoers.d",
		"cooldown_minutes": 60, "enabled": false,
	})
	require.Equal(t, http.StatusOK, rr.Code)
	var updated alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &updated))
	require.Equal(t, "/etc/sudoers.d", updated.MatchValue)
	require.False(t, updated.Enabled)

	// delete
	rr = callWithID(t, h.AlertRulesDeleteHandler, http.MethodDelete, "/api/v1/alerts/rules/{id}", created.ID, nil)
	require.Equal(t, http.StatusNoContent, rr.Code)

	// get after delete → 404
	rr = callWithID(t, h.AlertRuleGetHandler, http.MethodGet, "/api/v1/alerts/rules/{id}", created.ID, nil)
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestAlertRuleCreateRejectsInvalidSource(t *testing.T) {
	h := setupAlertsHandler(t)
	body := map[string]any{
		"name": "bad", "source": "carrier_pigeon",
		"match_type": "substring", "match_value": "x",
	}
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestAlertRuleCreateNodeScoped covers the node detail page's "alert on
// this node" flow: the scope is osquery's host_identifier, which is not
// necessarily a UUID. It used to fail validation and surface as a 500.
func TestAlertRuleCreateNodeScoped(t *testing.T) {
	h := setupAlertsHandler(t)
	body := map[string]any{
		"name": "web-server-01-inactive", "environment_id": 1, "source": "node_inactive",
		"node_uuid": "WEB-SERVER-01.CORP", "match_type": "substring",
		"match_field": "", "match_value": "", "cooldown_minutes": 0,
		"channel_ids": []uint{}, "enabled": true,
	}
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var created alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.Equal(t, "WEB-SERVER-01.CORP", created.NodeUUID)
}

// TestAlertRuleCreateInvalidIs400 pins bad input to 400 with the reason —
// validation errors used to fall through to a 500 saying only "error".
func TestAlertRuleCreateInvalidIs400(t *testing.T) {
	h := setupAlertsHandler(t)
	body := ruleBody()
	body["name"] = "   "
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "rule name is required")
}

func TestAlertChannelCRUDRoundTrip(t *testing.T) {
	h := setupAlertsHandler(t)

	body := map[string]any{
		"name": "soc-hook", "environment_id": 0, "type": "webhook", "enabled": true,
		"config": map[string]any{"url": "https://hooks.example.com/x", "secret": "hunter2"},
	}
	// create
	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", body)
	require.Equal(t, http.StatusCreated, rr.Code)
	var created alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.Equal(t, "soc-hook", created.Name)

	// list without reveal → secret redacted
	rr = call(t, h.AlertChannelsListHandler, http.MethodGet, "/api/v1/alerts/channels", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var list []alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(list[0].Config, &cfg))
	require.Equal(t, "***", cfg["secret"])
	require.Equal(t, "***", cfg["url"], "the webhook URL is a bearer secret")

	// list with reveal → secret visible
	rr = call(t, h.AlertChannelsListHandler, http.MethodGet, "/api/v1/alerts/channels?reveal=1", nil)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.NoError(t, json.Unmarshal(list[0].Config, &cfg))
	require.Equal(t, "hunter2", cfg["secret"])
	require.Equal(t, "https://hooks.example.com/x", cfg["url"])

	// update with redacted placeholder → secret preserved
	rr = callWithID(t, h.AlertChannelsUpdateHandler, http.MethodPut, "/api/v1/alerts/channels/{id}", created.ID, map[string]any{
		"name": "soc-hook", "environment_id": 0, "type": "webhook", "enabled": true,
		"config": map[string]any{"url": "https://hooks.example.com/y", "secret": "***"},
	})
	require.Equal(t, http.StatusOK, rr.Code)
	var updated alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &updated))
	require.NoError(t, json.Unmarshal(updated.Config, &cfg))
	require.Equal(t, "https://hooks.example.com/y", cfg["url"])
	require.Equal(t, "hunter2", cfg["secret"], "placeholder must merge the stored secret")
}

func revealedChannelConfig(t *testing.T, h *HandlersApi) map[string]any {
	t.Helper()
	rr := call(t, h.AlertChannelsListHandler, http.MethodGet, "/api/v1/alerts/channels?reveal=1", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var list []alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 1)
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(list[0].Config, &cfg))
	return cfg
}

func TestAlertChannelUpdateURLSecret(t *testing.T) {
	h := setupAlertsHandler(t)
	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", map[string]any{
		"name": "soc-hook", "type": "webhook", "enabled": true,
		"config": map[string]any{"url": "https://hooks.example.com/x", "secret": "hunter2"},
	})
	require.Equal(t, http.StatusCreated, rr.Code)
	var created alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	update := func(cfg map[string]any) {
		rr := callWithID(t, h.AlertChannelsUpdateHandler, http.MethodPut, "/api/v1/alerts/channels/{id}", created.ID, map[string]any{
			"name": "soc-hook", "type": "webhook", "enabled": true, "config": cfg,
		})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}

	update(map[string]any{"url": "***", "secret": "***"})
	cfg := revealedChannelConfig(t, h)
	require.Equal(t, "https://hooks.example.com/x", cfg["url"])
	require.Equal(t, "hunter2", cfg["secret"])

	update(map[string]any{"url": "https://hooks.example.com/new", "secret": "***"})
	cfg = revealedChannelConfig(t, h)
	require.Equal(t, "https://hooks.example.com/new", cfg["url"])
	require.Equal(t, "hunter2", cfg["secret"])
}

func TestAlertChannelTestMergesStoredURL(t *testing.T) {
	h := setupAlertsHandler(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", map[string]any{
		"name": "hook", "type": "webhook", "enabled": true,
		"config": json.RawMessage(fmt.Sprintf(`{"url":%q,"timeoutSeconds":5,"allowPrivateTargets":true}`, srv.URL)),
	})
	require.Equal(t, http.StatusCreated, rr.Code)
	var created alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))

	rr = call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"id": created.ID, "type": "webhook",
		"config": json.RawMessage(`{"url":"***","timeoutSeconds":5,"allowPrivateTargets":true}`),
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, 1, hits, "stored URL must be merged into the test send")
}

func TestAlertChannelRejectsBadConfig(t *testing.T) {
	h := setupAlertsHandler(t)
	body := map[string]any{
		"name": "broken", "type": "webhook", "enabled": true,
		"config": "{not json",
	}
	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", body)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestAlertChannelTestHandler covers the editor's "Send test" button: a
// working relay answers 200, a refused one is 502 (the relay's fault, not
// the operator's input), and an unknown type is 400.
func TestAlertChannelTestHandler(t *testing.T) {
	h := setupAlertsHandler(t)
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rr := call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"type":   "webhook",
		"config": json.RawMessage(fmt.Sprintf(`{"url":%q,"timeoutSeconds":5,"allowPrivateTargets":true}`, srv.URL)),
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Contains(t, string(got), "osctrl-channel-test")

	// Nothing listening → the relay refused, 502.
	rr = call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"type":   "webhook",
		"config": json.RawMessage(`{"url":"http://127.0.0.1:1/x","timeoutSeconds":1,"allowPrivateTargets":true}`),
	})
	require.Equal(t, http.StatusBadGateway, rr.Code)

	rr = call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"type": "carrier_pigeon", "config": json.RawMessage(`{}`),
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "carrier_pigeon", "a 400 has to name what was rejected")

	// A config the registry refuses to build reports the reason, not a
	// bare "invalid value" — here, the private-target guard.
	rr = call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"type":   "webhook",
		"config": json.RawMessage(`{"url":"http://127.0.0.1:9/x"}`),
	})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "allowPrivateTargets")
}

// TestAlertChannelTestMergesStoredSecret pins the edit case: the form
// reads secrets back as "***", so testing an untouched secret has to send
// the stored one instead of the placeholder.
func TestAlertChannelTestMergesStoredSecret(t *testing.T) {
	h := setupAlertsHandler(t)
	var signature string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-Osctrl-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", map[string]any{
		"name": "signed-hook", "type": "webhook", "enabled": true,
		"config": json.RawMessage(fmt.Sprintf(`{"url":%q,"secret":"s3cr3t","timeoutSeconds":5,"allowPrivateTargets":true}`, srv.URL)),
	})
	require.Equal(t, http.StatusCreated, rr.Code)
	var created alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))

	rr = call(t, h.AlertChannelsTestHandler, http.MethodPost, "/api/v1/alerts/channels/test", map[string]any{
		"id": created.ID, "type": "webhook",
		"config": json.RawMessage(fmt.Sprintf(`{"url":%q,"secret":"***","timeoutSeconds":5,"allowPrivateTargets":true}`, srv.URL)),
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotEmpty(t, signature, "stored HMAC secret must be merged into the test send")
}

func TestAlertChannelTypesHandler(t *testing.T) {
	h := setupAlertsHandler(t)
	rr := call(t, h.AlertChannelsTypesHandler, http.MethodGet, "/api/v1/alerts/channels/types", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var specs []struct {
		Type         string   `json:"type"`
		HasSecret    bool     `json:"has_secret"`
		SecretFields []string `json:"secret_fields"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &specs))
	require.Len(t, specs, 2)
	for _, sp := range specs {
		if sp.Type == "webhook" {
			require.Equal(t, []string{"url", "secret"}, sp.SecretFields)
		}
	}
}

func TestAlertHistoryHandler(t *testing.T) {
	h := setupAlertsHandler(t)
	require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleName: "r", Entity: "e", Detail: "d"}))
	rr := call(t, h.AlertHistoryHandler, http.MethodGet, "/api/v1/alerts/history", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	var rows []alerts.AlertHistory
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, "r", rows[0].RuleName)
}

func TestAlertsApplyQueuesServiceCommand(t *testing.T) {
	h := setupAlertsHandler(t)
	rr := call(t, h.AlertsApplyHandler, http.MethodPost, "/api/v1/alerts/apply", nil)
	require.Equal(t, http.StatusAccepted, rr.Code)

	// The command must be consumable by osctrl-tls.
	cmd, ok, err := h.ServiceCommands.ConsumeNext(config.ServiceTLS, "osctrl-tls", time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, servicecommands.ActionReloadAlerts, cmd.Action)
}

// A vulnerability rule on a deployment without vulnerability monitoring
// would never fire; refuse it instead of storing a silent rule.
func TestAlertRuleVulnFindingNeedsTheFeature(t *testing.T) {
	h := setupAlertsHandler(t)
	body := map[string]any{"name": "kev", "source": "vuln_finding", "vuln_min_severity": "kev", "enabled": true}
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "vulnerability monitoring")
}

func TestAlertRuleVulnFindingRoundTrip(t *testing.T) {
	h := setupAlertsHandler(t)
	h.Vulns = vulns.NewReader(nil, 0) // only its presence is checked
	body := map[string]any{"name": "kev", "source": "vuln_finding", "vuln_min_severity": "kev", "enabled": true}
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var created alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.Equal(t, "kev", created.VulnMinSeverity)

	body["vuln_min_severity"] = "High"
	rr = callWithID(t, h.AlertRulesUpdateHandler, http.MethodPut, "/api/v1/alerts/rules/1", created.ID, body)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var updated alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &updated))
	require.Equal(t, "high", updated.VulnMinSeverity)
}

// An existing vulnerability rule stays editable (to disable it) after
// vulnerability monitoring is turned off; turning another rule into one
// still needs the feature.
func TestAlertRuleVulnFindingEditableWhenFeatureOff(t *testing.T) {
	h := setupAlertsHandler(t)
	h.Vulns = vulns.NewReader(nil, 0)
	body := map[string]any{"name": "kev", "source": "vuln_finding", "vuln_min_severity": "kev", "enabled": true}
	rr := call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", body)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var vulnRule alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &vulnRule))
	logBody := map[string]any{"name": "log", "source": "result_log", "match_type": "substring", "match_value": "x", "enabled": true}
	rr = call(t, h.AlertRulesCreateHandler, http.MethodPost, "/api/v1/alerts/rules", logBody)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var logRule alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &logRule))

	h.Vulns = nil
	body["enabled"] = false
	rr = callWithID(t, h.AlertRulesUpdateHandler, http.MethodPut, "/api/v1/alerts/rules/1", vulnRule.ID, body)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	logBody["source"], logBody["vuln_min_severity"] = "vuln_finding", "kev"
	rr = callWithID(t, h.AlertRulesUpdateHandler, http.MethodPut, "/api/v1/alerts/rules/2", logRule.ID, logBody)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
}

// callAlertsAs runs a handler as a given user with an optional JSON body and {id}.
func callAlertsAs(t *testing.T, h http.HandlerFunc, user, method string, body any, id uint) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(method, "/api/v1/alerts", bytes.NewReader(raw)).WithContext(alertsCtx(user))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("id", strconv.FormatUint(uint64(id), 10))
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func setupAlertRoles(t *testing.T) *HandlersApi {
	t.Helper()
	h := setupAlertsHandler(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "alerty", AlertAdmin: true}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	return h
}

func TestAlertAdminManagesStatusRules(t *testing.T) {
	h := setupAlertRoles(t)
	rr := callAlertsAs(t, h.AlertRulesCreateHandler, "alerty", http.MethodPost, map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	}, 0)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	rr = callAlertsAs(t, h.AlertChannelsCreateHandler, "alerty", http.MethodPost, map[string]any{
		"name": "hook", "type": "webhook", "config": map[string]any{"url": "https://example.com/hook"}, "enabled": true,
	}, 0)
	require.Less(t, rr.Code, 300, rr.Body.String())
}

func TestAlertAdminCannotCreateLogContentRule(t *testing.T) {
	h := setupAlertRoles(t)
	rr := callAlertsAs(t, h.AlertRulesCreateHandler, "alerty", http.MethodPost, ruleBody(), 0)
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.Contains(t, rr.Body.String(), "log-content alert rules require superuser")
	rr = callAlertsAs(t, h.AlertRulesCreateHandler, "alice", http.MethodPost, ruleBody(), 0)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
}

func TestAlertAdminCannotUpdateRuleToLogContent(t *testing.T) {
	h := setupAlertRoles(t)
	rr := callAlertsAs(t, h.AlertRulesCreateHandler, "alerty", http.MethodPost, map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	}, 0)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var created alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	body := ruleBody()
	body["source"] = "query_log"
	rr = callAlertsAs(t, h.AlertRulesUpdateHandler, "alerty", http.MethodPut, body, created.ID)
	require.Equal(t, http.StatusForbidden, rr.Code)
	// An existing log-content rule is not editable by a non-superuser either.
	rr = callAlertsAs(t, h.AlertRulesCreateHandler, "alice", http.MethodPost, ruleBody(), 0)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var logRule alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &logRule))
	rr = callAlertsAs(t, h.AlertRulesUpdateHandler, "alerty", http.MethodPut, map[string]any{
		"name": "x", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	}, logRule.ID)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestReadOnlyReadsAlertsNotWrites(t *testing.T) {
	h := setupAlertRoles(t)
	rr := callAlertsAs(t, h.AlertRulesListHandler, "ro", http.MethodGet, nil, 0)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = callAlertsAs(t, h.AlertRulesCreateHandler, "ro", http.MethodPost, map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	}, 0)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func mustCreateRuleAs(t *testing.T, h *HandlersApi, user string, body map[string]any) alertRuleDTO {
	t.Helper()
	rr := callAlertsAs(t, h.AlertRulesCreateHandler, user, http.MethodPost, body, 0)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var out alertRuleDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func mustCreateChannelAs(t *testing.T, h *HandlersApi, user, name string) alertChannelDTO {
	t.Helper()
	rr := callAlertsAs(t, h.AlertChannelsCreateHandler, user, http.MethodPost, map[string]any{
		"name": name, "type": "webhook", "config": map[string]any{"url": "https://example.com/" + name}, "enabled": true,
	}, 0)
	require.Less(t, rr.Code, 300, rr.Body.String())
	var out alertChannelDTO
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func TestLogContentRulesAndChannelsProtected(t *testing.T) {
	h := setupAlertRoles(t)
	logCh := mustCreateChannelAs(t, h, "alice", "logch")
	plainCh := mustCreateChannelAs(t, h, "alice", "plainch")
	logBody := ruleBody()
	logBody["channel_ids"] = []uint{logCh.ID}
	logRule := mustCreateRuleAs(t, h, "alice", logBody)
	plainRule := mustCreateRuleAs(t, h, "alice", map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{plainCh.ID}, "enabled": true,
	})
	chBody := func(name string) map[string]any {
		return map[string]any{"name": name, "type": "webhook", "config": map[string]any{"url": "https://example.com/x"}, "enabled": true}
	}
	cases := []struct {
		name string
		fn   http.HandlerFunc
		verb string
		body any
		id   uint
		want int
	}{
		{"delete log rule", h.AlertRulesDeleteHandler, http.MethodDelete, nil, logRule.ID, http.StatusForbidden},
		{"update log channel", h.AlertChannelsUpdateHandler, http.MethodPut, chBody("renamed"), logCh.ID, http.StatusForbidden},
		{"delete log channel", h.AlertChannelsDeleteHandler, http.MethodDelete, nil, logCh.ID, http.StatusForbidden},
		{"update plain channel", h.AlertChannelsUpdateHandler, http.MethodPut, chBody("renamed"), plainCh.ID, http.StatusOK},
		{"delete plain rule", h.AlertRulesDeleteHandler, http.MethodDelete, nil, plainRule.ID, http.StatusNoContent},
		{"delete plain channel", h.AlertChannelsDeleteHandler, http.MethodDelete, nil, plainCh.ID, http.StatusNoContent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := callAlertsAs(t, c.fn, "alerty", c.verb, c.body, c.id)
			require.Equal(t, c.want, rr.Code, rr.Body.String())
			if c.want == http.StatusForbidden {
				require.Contains(t, rr.Body.String(), "log-content alert rules require superuser")
			}
		})
	}
	// A superuser still can.
	require.Equal(t, http.StatusOK, callAlertsAs(t, h.AlertChannelsUpdateHandler, "alice", http.MethodPut, chBody("renamed-by-root"), logCh.ID).Code)
	require.Equal(t, http.StatusNoContent, callAlertsAs(t, h.AlertRulesDeleteHandler, "alice", http.MethodDelete, nil, logRule.ID).Code)
}

func TestAlertHistoryHidesLogContentFromNonSuperuser(t *testing.T) {
	h := setupAlertRoles(t)
	logRule := mustCreateRuleAs(t, h, "alice", ruleBody())
	plainRule := mustCreateRuleAs(t, h, "alice", map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	})
	require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleID: logRule.ID, RuleName: "log", Detail: "secret log line"}))
	require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleID: plainRule.ID, RuleName: "plain", Detail: "node down"}))
	hist := func(user string) string {
		rr := callAlertsAs(t, h.AlertHistoryHandler, user, http.MethodGet, nil, 0)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		return rr.Body.String()
	}
	for _, u := range []string{"alerty", "ro"} {
		body := hist(u)
		require.Contains(t, body, "node down")
		require.NotContains(t, body, "secret log line")
	}
	body := hist("alice")
	require.Contains(t, body, "node down")
	require.Contains(t, body, "secret log line")
}

func TestAlertHistoryFailsClosedAndHonorsLimit(t *testing.T) {
	h := setupAlertRoles(t)
	logRule := mustCreateRuleAs(t, h, "alice", ruleBody())
	plainRule := mustCreateRuleAs(t, h, "alice", map[string]any{
		"name": "inactive", "source": "node_inactive", "cooldown_minutes": 30, "channel_ids": []uint{1}, "enabled": true,
	})
	// A row whose rule no longer exists.
	require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleID: 9999, RuleName: "gone", Detail: "orphan log line"}))
	// Newest rows are log-content, so a post-limit filter would return too few.
	for i := 0; i < 3; i++ {
		require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleID: plainRule.ID, RuleName: "plain", Detail: "node down"}))
	}
	for i := 0; i < 5; i++ {
		require.NoError(t, h.Alerts.RecordHistory(alerts.AlertHistory{RuleID: logRule.ID, RuleName: "log", Detail: "secret log line"}))
	}
	get := func(user, query string) []alerts.AlertHistory {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts/history"+query, nil).WithContext(alertsCtx(user))
		rr := httptest.NewRecorder()
		h.AlertHistoryHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var rows []alerts.AlertHistory
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
		return rows
	}
	rows := get("alerty", "?limit=2")
	require.Len(t, rows, 2)
	for _, r := range get("alerty", "") {
		require.Equal(t, plainRule.ID, r.RuleID)
	}
	require.Len(t, get("alerty", ""), 3)
	require.Len(t, get("alice", ""), 9) // superuser sees all, including the orphan
}

// Only a superuser may read channel secrets back, even with reveal=1.
func TestAlertChannelRevealSuperuserOnly(t *testing.T) {
	h := setupAlertRoles(t)
	ch := mustCreateChannelAs(t, h, "alice", "hook")
	secretOf := func(fn http.HandlerFunc, user, path string, list bool) any {
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(alertsCtx(user))
		req.SetPathValue("id", strconv.FormatUint(uint64(ch.ID), 10))
		rr := httptest.NewRecorder()
		fn(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var dto alertChannelDTO
		if list {
			var rows []alertChannelDTO
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
			require.Len(t, rows, 1)
			dto = rows[0]
		} else {
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &dto))
		}
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(dto.Config, &cfg))
		return cfg["url"]
	}
	for _, user := range []string{"ro", "alerty"} {
		require.Equal(t, "***", secretOf(h.AlertChannelsListHandler, user, "/api/v1/alerts/channels?reveal=1", true), user)
		require.Equal(t, "***", secretOf(h.AlertChannelsGetHandler, user, "/api/v1/alerts/channels/1?reveal=1", false), user)
	}
	require.Equal(t, "https://example.com/hook", secretOf(h.AlertChannelsListHandler, "alice", "/api/v1/alerts/channels?reveal=1", true))
	require.Equal(t, "https://example.com/hook", secretOf(h.AlertChannelsGetHandler, "alice", "/api/v1/alerts/channels/1?reveal=1", false))
}

// Test-sending a stored channel merges its secrets into the caller's config,
// so a log-content channel stays superuser-only here too.
func TestAlertChannelTestRefusesLogContentChannel(t *testing.T) {
	h := setupAlertRoles(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := json.RawMessage(fmt.Sprintf(`{"url":%q,"timeoutSeconds":5,"allowPrivateTargets":true}`, srv.URL))
	mk := func(name string) uint {
		rr := callAlertsAs(t, h.AlertChannelsCreateHandler, "alice", http.MethodPost, map[string]any{
			"name": name, "type": "webhook", "enabled": true, "config": cfg,
		}, 0)
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		var out alertChannelDTO
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		return out.ID
	}
	logCh, plainCh := mk("logch"), mk("plainch")
	logBody := ruleBody()
	logBody["channel_ids"] = []uint{logCh}
	mustCreateRuleAs(t, h, "alice", logBody)
	testBody := func(id uint) map[string]any {
		return map[string]any{"id": id, "type": "webhook", "config": json.RawMessage(`{"url":"***","timeoutSeconds":5,"allowPrivateTargets":true}`)}
	}
	rr := callAlertsAs(t, h.AlertChannelsTestHandler, "alerty", http.MethodPost, testBody(logCh), 0)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.Equal(t, 0, hits)
	rr = callAlertsAs(t, h.AlertChannelsTestHandler, "alerty", http.MethodPost, testBody(plainCh), 0)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, 1, hits)
	rr = callAlertsAs(t, h.AlertChannelsTestHandler, "alice", http.MethodPost, testBody(logCh), 0)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// A log-content rule with unreadable channel IDs might target any channel.
func TestChannelGuardFailsClosedOnMalformedRule(t *testing.T) {
	h := setupAlertRoles(t)
	ch := mustCreateChannelAs(t, h, "alice", "plainch")
	require.NoError(t, h.Alerts.DB.Create(&alerts.AlertRule{Name: "broken", Source: alerts.SourceResultLog, MatchType: "substring", MatchValue: "x", ChannelIDs: "{not json"}).Error)
	rr := callAlertsAs(t, h.AlertChannelsDeleteHandler, "alerty", http.MethodDelete, nil, ch.ID)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
}
