package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupHealthHandler(t *testing.T) (*HandlersApi, *health.Manager) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	userManager := users.CreateUserManager(db)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice", Admin: true}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", false)
	require.NoError(t, err)
	mgr := health.NewManager(db)
	h := CreateHandlersApi(
		WithDB(db),
		WithUsers(userManager),
		WithAuditLog(auditLog),
		WithDebugHTTP(&config.YAMLConfigurationDebug{}),
		WithHealth(mgr),
		WithHealthVersions(health.NewVersionCache("0.5.8")),
		WithStartedAt(time.Now().Add(-time.Hour)),
	)
	return h, mgr
}

func healthRequest(user string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/status", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	return req.WithContext(alertsCtx(user))
}

func TestHealthStatusRejectsNonAdmin(t *testing.T) {
	h, _ := setupHealthHandler(t)
	rr := httptest.NewRecorder()
	h.HealthStatusHandler(rr, healthRequest("bob"))
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestHealthStatusReturns503WhenDisabled(t *testing.T) {
	h, _ := setupHealthHandler(t)
	h.Health = nil
	rr := httptest.NewRecorder()
	h.HealthStatusHandler(rr, healthRequest("alice"))
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestHealthStatusReportsComponents(t *testing.T) {
	h, mgr := setupHealthHandler(t)
	require.NoError(t, mgr.Report(health.ServiceStatus{
		Service: "tls", Version: "0.5.8",
		StartedAt: time.Now().Add(-2 * time.Hour), ReportedAt: time.Now(),
		Goroutines: 71,
		Payload:    `{"alerts":{"enabled":true,"queue_depth":0,"queue_capacity":8192,"dispatched":9}}`,
	}))

	rr := httptest.NewRecorder()
	h.HealthStatusHandler(rr, healthRequest("alice"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var resp healthStatusResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	byID := map[string]health.Component{}
	for _, c := range resp.Components {
		byID[c.ID] = c
	}
	require.Contains(t, byID, "database")
	require.Contains(t, byID, "redis")
	require.Contains(t, byID, "api")
	require.Equal(t, health.StatusOperational, byID["api"].Status)
	require.Equal(t, health.StatusOperational, byID["tls"].Status)
	require.Equal(t, health.StatusOperational, byID["workers"].Status)
	require.Equal(t, "0.5.8", resp.Upgrade.Current)
	require.False(t, resp.Upgrade.Skew)
}

func TestHealthStatusFlagsMissingTLS(t *testing.T) {
	h, _ := setupHealthHandler(t)
	rr := httptest.NewRecorder()
	h.HealthStatusHandler(rr, healthRequest("alice"))
	require.Equal(t, http.StatusOK, rr.Code)

	var resp healthStatusResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	for _, c := range resp.Components {
		if c.ID == "tls" {
			require.Equal(t, health.StatusUnknown, c.Status)
			require.Contains(t, c.Summary, "--health-enabled")
			return
		}
	}
	t.Fatal("tls component missing from the response")
}
