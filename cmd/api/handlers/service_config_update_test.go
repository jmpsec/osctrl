package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/serviceconfig"
	"github.com/jmpsec/osctrl/pkg/users"
)

func setupServiceConfigUpdateHandler(t *testing.T) (*HandlersApi, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	userManager := users.CreateUserManager(db)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice", Admin: true}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	// Enabled: with false the manager records nothing, and the audit test
	// below would pass vacuously.
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)

	mgr := serviceconfig.NewServiceConfigManager(db)
	require.NoError(t, mgr.Seed(config.ServiceAPI, &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{Listener: "127.0.0.1", Port: 9000, Host: "osctrl.net", LogLevel: "info"},
		DB:      &config.YAMLConfigurationDB{Type: config.DBTypeSQLite, Name: "osctrl"},
	}, serviceconfig.NoEnvironmentID))

	return CreateHandlersApi(
		WithUsers(userManager),
		WithAuditLog(auditLog),
		WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		WithServiceConfig(mgr),
	), db
}

func updateSection(t *testing.T, h *HandlersApi, user, section string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/service-config/api/"+section, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("service", config.ServiceAPI)
	req.SetPathValue("section", section)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
	rr := httptest.NewRecorder()
	h.ServiceConfigUpdateHandler(rr, req)
	return rr
}

func TestServiceConfigPatchPinsOnlyTheNamedField(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)

	rr := updateSection(t, h, "alice", "service", map[string]any{
		"patch": map[string]any{"LogLevel": "debug"},
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var row serviceconfig.ServiceConfig
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &row))
	require.Equal(t, serviceconfig.SourceDB, row.Source)
	require.JSONEq(t, `["LogLevel"]`, row.Overrides, "only the field the caller named is pinned")
	require.Contains(t, row.Value, `"LogLevel":"debug"`)
}

func TestServiceConfigResetReleasesAPinnedField(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)
	require.Equal(t, http.StatusOK, updateSection(t, h, "alice", "service",
		map[string]any{"patch": map[string]any{"LogLevel": "debug"}}).Code)

	rr := updateSection(t, h, "alice", "service", map[string]any{"reset": []string{"LogLevel"}})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var row serviceconfig.ServiceConfig
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &row))
	require.Equal(t, serviceconfig.SourceYAML, row.Source, "releasing the last pin returns the row to the file's control")
	require.Empty(t, row.Overrides)
}

// Existing clients — automation, scripts — send a whole value. That must keep
// working exactly as before, including pinning everything.
func TestServiceConfigWholeValueStillWorks(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)

	rr := updateSection(t, h, "alice", "service", map[string]any{
		"value": map[string]any{"Listener": "127.0.0.1", "Port": 9100, "Host": "osctrl.net", "LogLevel": "warn"},
	})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var row serviceconfig.ServiceConfig
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &row))
	require.Equal(t, serviceconfig.SourceDB, row.Source)
	require.Empty(t, row.Overrides, "an empty pin list on a db row means every field is pinned")
}

func TestServiceConfigRejectsAmbiguousAndEmptyBodies(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)

	both := updateSection(t, h, "alice", "service", map[string]any{
		"value": map[string]any{"Port": 1},
		"patch": map[string]any{"LogLevel": "debug"},
	})
	require.Equal(t, http.StatusBadRequest, both.Code, "value together with patch is ambiguous about which one was meant")

	none := updateSection(t, h, "alice", "service", map[string]any{})
	require.Equal(t, http.StatusBadRequest, none.Code)
}

func TestServiceConfigPatchNamesAnUnknownField(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)

	rr := updateSection(t, h, "alice", "service", map[string]any{"patch": map[string]any{"Prot": 9100}})
	require.Equal(t, http.StatusBadRequest, rr.Code, "a typo is the caller's mistake, not a server error")
	require.Contains(t, rr.Body.String(), "Prot", "the response must say which field was not recognised")
}

func TestServiceConfigPatchRefusesNonEditableSections(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)
	rr := updateSection(t, h, "alice", "db", map[string]any{"patch": map[string]any{"Password": "x"}})
	require.Equal(t, http.StatusConflict, rr.Code)
}

func TestServiceConfigUpdateRequiresAdmin(t *testing.T) {
	h, _ := setupServiceConfigUpdateHandler(t)
	rr := updateSection(t, h, "bob", "service", map[string]any{"patch": map[string]any{"LogLevel": "debug"}})
	require.Equal(t, http.StatusForbidden, rr.Code)
}

// The audit trail records WHICH fields changed, never their values: a patch can
// carry anything an editable section holds.
func TestServiceConfigPatchAuditsFieldNamesNotValues(t *testing.T) {
	h, db := setupServiceConfigUpdateHandler(t)
	const secretish = "value-that-must-not-reach-the-audit-log"

	require.Equal(t, http.StatusOK, updateSection(t, h, "alice", "service",
		map[string]any{"patch": map[string]any{"Host": secretish}}).Code)

	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	joined := strings.Join(lines, "\n")
	require.Contains(t, joined, "patch service-config api/service")
	require.Contains(t, joined, "Host", "the changed field is named")
	require.NotContains(t, joined, secretish, "its value is not")
}
