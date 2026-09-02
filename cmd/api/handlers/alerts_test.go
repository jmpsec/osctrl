package handlers

import (
	"bytes"
	"context"
	"encoding/json"
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
	require.Equal(t, "https://hooks.example.com/x", cfg["url"])

	// list with reveal → secret visible
	rr = call(t, h.AlertChannelsListHandler, http.MethodGet, "/api/v1/alerts/channels?reveal=1", nil)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.NoError(t, json.Unmarshal(list[0].Config, &cfg))
	require.Equal(t, "hunter2", cfg["secret"])

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

func TestAlertChannelRejectsBadConfig(t *testing.T) {
	h := setupAlertsHandler(t)
	body := map[string]any{
		"name": "broken", "type": "webhook", "enabled": true,
		"config": "{not json",
	}
	rr := call(t, h.AlertChannelsCreateHandler, http.MethodPost, "/api/v1/alerts/channels", body)
	require.Equal(t, http.StatusBadRequest, rr.Code)
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
