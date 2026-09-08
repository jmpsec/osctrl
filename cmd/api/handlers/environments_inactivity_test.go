package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentInactiveHoursAPI(t *testing.T) {
	db, h, env, _ := setupConsoleHandlers(t)
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, "api", true)
	require.NoError(t, err)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 168, 0))
	require.NoError(t, h.Users.CreatePermission(users.UserPermission{Username: "bob", AccessType: int(users.UserLevel), AccessValue: true, Environment: env.UUID, EnvironmentID: env.ID}))
	other := environments.TLSEnvironment{Name: "other", UUID: "other-uuid"}
	require.NoError(t, db.Create(&other).Error)

	run := func(method, identifier, username, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := consoleRequest(method, "/api/v1/environments/inactive-hours/"+identifier, []byte(body), username)
		req.SetPathValue("env", identifier)
		rr := httptest.NewRecorder()
		switch method {
		case http.MethodGet:
			h.EnvironmentInactiveHoursHandler(rr, req)
		case http.MethodPut:
			h.EnvironmentInactiveHoursSetHandler(rr, req)
		case http.MethodDelete:
			h.EnvironmentInactiveHoursResetHandler(rr, req)
		}
		return rr
	}
	check := func(rr *httptest.ResponseRecorder, hours int64, source string) {
		t.Helper()
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var policy settings.InactivityPolicy
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &policy))
		require.Equal(t, hours, policy.InactiveHours)
		require.Equal(t, source, policy.Source)
		if source == "environment" {
			require.NotNil(t, policy.OverrideHours)
			require.Equal(t, hours, *policy.OverrideHours)
		} else {
			require.Nil(t, policy.OverrideHours)
		}
	}

	check(run(http.MethodGet, env.Name, "bob", ""), 168, "global")
	check(run(http.MethodPut, env.UUID, "alice", `{"inactive_hours":2}`), 2, "environment")
	check(run(http.MethodGet, env.Name, "bob", ""), 2, "environment")
	require.Equal(t, int64(168), h.Settings.InactiveHours(other.ID))

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		require.Equal(t, http.StatusForbidden, run(method, other.Name, "alice", `{"inactive_hours":2}`).Code)
		require.Equal(t, http.StatusNotFound, run(method, "missing", "alice", `{"inactive_hours":2}`).Code)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		require.Equal(t, http.StatusForbidden, run(method, env.Name, "bob", `{"inactive_hours":2}`).Code)
	}
	for _, body := range []string{
		`{}`, `null`, `{"inactive_hours":null}`, `{"inactive_hours":0}`, `{"inactive_hours":-1}`,
		`{"inactive_hours":2.5}`, `{"inactive_hours":"2"}`, `{"inactive_hours":2562048}`,
		`{"inactive_hours":2,"extra":true}`, `{"inactive_hours":2} {}`, strings.Repeat(" ", 1025),
	} {
		rr := run(http.MethodPut, env.Name, "alice", body)
		require.Equal(t, http.StatusBadRequest, rr.Code, body+": "+rr.Body.String())
	}
	check(run(http.MethodGet, env.Name, "alice", ""), 2, "environment")
	check(run(http.MethodDelete, env.Name, "alice", ""), 168, "global")
	check(run(http.MethodDelete, env.Name, "alice", ""), 168, "global")
	var logs []auditlog.AuditLog
	require.NoError(t, db.Where("environment_id = ? AND log_type = ?", env.ID, auditlog.LogTypeEnvironment).Find(&logs).Error)
	encoded, err := json.Marshal(logs)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "168 (global) -")
	require.Contains(t, string(encoded), "2 (environment)")
}

func TestGlobalInactiveHoursAPIValidation(t *testing.T) {
	db, h, _, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 72, 0))
	patch := func(username, body string) *httptest.ResponseRecorder {
		req := consoleRequest(http.MethodPatch, "/api/v1/settings/api/inactive_hours", []byte(body), username)
		req.SetPathValue("service", config.ServiceAPI)
		req.SetPathValue("name", settings.InactiveHours)
		rr := httptest.NewRecorder()
		h.SettingPatchHandler(rr, req)
		return rr
	}
	require.Equal(t, http.StatusForbidden, patch("alice", `{"integer":2}`).Code)
	require.NoError(t, h.Users.ChangeAdmin("alice", true))
	for _, body := range []string{`{"integer":0}`, `{"integer":-1}`, `{"integer":2.5}`, `{"integer":2562048}`, `{"integer":null}`} {
		rr := patch("alice", body)
		require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	}
	rr := patch("alice", `{"integer":24}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, int64(24), h.Settings.InactiveHours(0))
}
