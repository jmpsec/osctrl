package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupSettingsPatch(t *testing.T) (*HandlersApi, *settings.Settings) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	um := users.CreateUserManager(db)
	require.NoError(t, um.Create(users.AdminUser{Username: "alice", Admin: true}))
	require.NoError(t, um.Create(users.AdminUser{Username: "bob"}))
	al, err := auditlog.CreateAuditLogManager(db, "osctrl-api", false)
	require.NoError(t, err)
	sm := settings.NewSettings(db)
	require.NoError(t, sm.NewStringValue(config.ServiceAPI, "s", "old", settings.NoEnvironmentID))
	require.NoError(t, sm.NewBooleanValue(config.ServiceAPI, "b", false, settings.NoEnvironmentID))
	require.NoError(t, sm.NewIntegerValue(config.ServiceAPI, "i", 1, settings.NoEnvironmentID))
	require.NoError(t, sm.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, settings.NoEnvironmentID))
	require.NoError(t, sm.NewIntegerValue(config.ServiceAPI, settings.AuditLogRetentionDays, 90, settings.NoEnvironmentID))
	h := CreateHandlersApi(WithUsers(um), WithAuditLog(al), WithSettings(sm), WithDebugHTTP(&config.YAMLConfigurationDebug{}))
	return h, sm
}

func TestSettingPatchHandler(t *testing.T) {
	h, sm := setupSettingsPatch(t)
	cases := []struct {
		name, user, setting, body string
		status                    int
		contains                  string
		check                     func(t *testing.T)
	}{
		{"missing setting", "alice", "nope", `{"string":"x"}`, 404, "setting not found", nil},
		{"string mismatch", "alice", "s", `{"integer":1}`, 400, "setting is string — provide `string`", nil},
		{"boolean mismatch", "alice", "b", `{"string":"x"}`, 400, "setting is boolean — provide `boolean`", nil},
		{"integer mismatch", "alice", "i", `{"boolean":true}`, 400, "setting is integer — provide `integer`", nil},
		{"malformed body", "alice", "s", `{`, 400, "error parsing PATCH body", nil},
		{"non-admin", "bob", "s", `{"string":"x"}`, 403, "no access", nil},
		{"inactive_hours below", "alice", settings.InactiveHours, `{"integer":0}`, 400, "inactive_hours", nil},
		{"inactive_hours min", "alice", settings.InactiveHours, `{"integer":1}`, 200, "", nil},
		{"inactive_hours max", "alice", settings.InactiveHours, `{"integer":` + strconv.FormatInt(settings.MaxInactiveHours, 10) + `}`, 200, "", nil},
		{"inactive_hours above", "alice", settings.InactiveHours, `{"integer":` + strconv.FormatInt(settings.MaxInactiveHours+1, 10) + `}`, 400, "inactive_hours", nil},
		{"retention below", "alice", settings.AuditLogRetentionDays, `{"integer":0}`, 400, "audit_log_retention_days", nil},
		{"retention min", "alice", settings.AuditLogRetentionDays, `{"integer":1}`, 200, "", nil},
		{"retention max", "alice", settings.AuditLogRetentionDays, `{"integer":36500}`, 200, "", nil},
		{"retention above", "alice", settings.AuditLogRetentionDays, `{"integer":36501}`, 400, "audit_log_retention_days", nil},
		{"string ok", "alice", "s", `{"string":"new"}`, 200, "", func(t *testing.T) {
			v, err := sm.RetrieveValue(config.ServiceAPI, "s", settings.NoEnvironmentID)
			require.NoError(t, err)
			require.Equal(t, "new", v.String)
		}},
		{"boolean ok", "alice", "b", `{"boolean":true}`, 200, "", func(t *testing.T) {
			v, err := sm.RetrieveValue(config.ServiceAPI, "b", settings.NoEnvironmentID)
			require.NoError(t, err)
			require.True(t, v.Boolean)
		}},
		{"integer ok", "alice", "i", `{"integer":42}`, 200, "", func(t *testing.T) {
			v, err := sm.RetrieveValue(config.ServiceAPI, "i", settings.NoEnvironmentID)
			require.NoError(t, err)
			require.Equal(t, int64(42), v.Integer)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/api/v1/settings/api/"+c.setting, bytes.NewBufferString(c.body)).
				WithContext(context.WithValue(context.Background(), ContextKey(contextAPI), ContextValue{ctxUser: c.user}))
			req.SetPathValue("service", config.ServiceAPI)
			req.SetPathValue("name", c.setting)
			w := httptest.NewRecorder()
			h.SettingPatchHandler(w, req)
			require.Equal(t, c.status, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), c.contains)
			if c.check != nil {
				c.check(t)
			}
		})
	}
}
