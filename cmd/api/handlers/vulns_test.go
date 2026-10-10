package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/vulns"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// alice is env-A admin only; root is a super admin; bob has no permissions.
func setupVulnHandlers(t *testing.T) (*HandlersApi, *gorm.DB, environments.TLSEnvironment, environments.TLSEnvironment) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesmgr := nodes.CreateNodes(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	require.NoError(t, vulns.Migrate(db))

	envA := environments.TLSEnvironment{UUID: "env-a", Name: "a"}
	envB := environments.TLSEnvironment{UUID: "env-b", Name: "b"}
	require.NoError(t, db.Create(&envA).Error)
	require.NoError(t, db.Create(&envB).Error)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "NODE-A", EnvironmentID: envA.ID, Environment: envA.Name}).Error)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "NODE-B", EnvironmentID: envB.ID, Environment: envB.Name}).Error)

	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "root", Admin: true}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username: "alice", AccessType: int(users.AdminLevel), AccessValue: true, Environment: envA.UUID, EnvironmentID: envA.ID,
	}))

	require.NoError(t, db.Create(&vulns.Advisory{ID: "DSA-1", Severity: vulns.SeverityCritical, Summary: "<script>alert(1)</script>"}).Error)
	require.NoError(t, db.Create(&[]vulns.Finding{
		{NodeUUID: "NODE-A", EnvironmentID: envA.ID, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", Severity: vulns.SeverityCritical, Confidence: vulns.ConfidenceConfirmed},
		{NodeUUID: "NODE-B", EnvironmentID: envB.ID, AdvisoryID: "DSA-1", Ecosystem: "Debian:12", Package: "openssl", Severity: vulns.SeverityCritical, Confidence: vulns.ConfidenceConfirmed},
	}).Error)

	h := CreateHandlersApi(
		WithDB(db), WithEnvs(envs), WithUsers(userManager), WithNodes(nodesmgr),
		WithAuditLog(auditLog), WithVulns(vulns.NewReader(db, 0)),
	)
	return h, db, envA, envB
}

func vulnRequest(method, target, user string, path map[string]string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range path {
		req.SetPathValue(k, v)
	}
	return req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
}

func TestVulnFindingsAreEnvironmentScoped(t *testing.T) {
	h, _, envA, envB := setupVulnHandlers(t)

	rr := httptest.NewRecorder()
	h.VulnFindingsHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var page VulnFindingsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page))
	require.Len(t, page.Findings, 1)
	require.Equal(t, "NODE-A", page.Findings[0].NodeUUID)

	rr = httptest.NewRecorder()
	h.VulnFindingsHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envB.Name}))
	require.Equal(t, http.StatusForbidden, rr.Code)

	rr = httptest.NewRecorder()
	h.VulnFindingsHandler(rr, vulnRequest(http.MethodGet, "/x", "bob", map[string]string{"env": envA.Name}))
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestVulnFindingsRejectsUnknownFilterValues(t *testing.T) {
	h, _, envA, _ := setupVulnHandlers(t)
	rr := httptest.NewRecorder()
	h.VulnFindingsHandler(rr, vulnRequest(http.MethodGet, "/x?severity=catastrophic", "alice", map[string]string{"env": envA.Name}))
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestVulnAdvisoryListsOnlyNodesInTheRequestedEnvironment(t *testing.T) {
	h, _, envA, _ := setupVulnHandlers(t)
	rr := httptest.NewRecorder()
	h.VulnAdvisoryHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name, "id": "DSA-1"}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var d vulns.AdvisoryDetail
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &d))
	require.Len(t, d.Findings, 1)
	require.Equal(t, "NODE-A", d.Findings[0].NodeUUID)
	require.Equal(t, "<script>alert(1)</script>", d.Advisory.Summary, "feed text is returned as data; the SPA renders it as text")

	rr = httptest.NewRecorder()
	h.VulnAdvisoryHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name, "id": "NOPE"}))
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestVulnNodeRefusesANodeFromAnotherEnvironment(t *testing.T) {
	h, _, envA, _ := setupVulnHandlers(t)
	rr := httptest.NewRecorder()
	h.VulnNodeHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name, "uuid": "NODE-B"}))
	require.Equal(t, http.StatusForbidden, rr.Code)

	rr = httptest.NewRecorder()
	h.VulnNodeHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name, "uuid": "NODE-A"}))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVulnFeedsAndSyncRequestAreSuperAdminOnly(t *testing.T) {
	h, db, _, _ := setupVulnHandlers(t)

	rr := httptest.NewRecorder()
	h.VulnFeedsHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", nil))
	require.Equal(t, http.StatusForbidden, rr.Code)

	rr = httptest.NewRecorder()
	h.VulnSyncRequestHandler(rr, vulnRequest(http.MethodPost, "/x", "alice", nil))
	require.Equal(t, http.StatusForbidden, rr.Code, "an environment admin cannot trigger outbound downloads")

	rr = httptest.NewRecorder()
	h.VulnSyncRequestHandler(rr, vulnRequest(http.MethodPost, "/x", "root", nil))
	require.Equal(t, http.StatusAccepted, rr.Code, rr.Body.String())

	var ws vulns.WorkerState
	require.NoError(t, db.First(&ws).Error)
	require.NotNil(t, ws.SyncRequestedAt)
	var lines []string
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Pluck("line", &lines).Error)
	require.Contains(t, strings.Join(lines, "\n"), "vulnerability feed sync")

	rr = httptest.NewRecorder()
	h.VulnFeedsHandler(rr, vulnRequest(http.MethodGet, "/x", "root", nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestVulnHandlersAnswer503WhenDisabled(t *testing.T) {
	h, _, envA, _ := setupVulnHandlers(t)
	h.Vulns = nil
	rr := httptest.NewRecorder()
	h.VulnFindingsHandler(rr, vulnRequest(http.MethodGet, "/x", "alice", map[string]string{"env": envA.Name}))
	require.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestFeaturesAdvertiseVulnerabilities(t *testing.T) {
	h, _, _, _ := setupVulnHandlers(t)
	rr := httptest.NewRecorder()
	h.FeaturesHandler(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	var f FeaturesResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &f))
	require.True(t, f.Vulnerabilities)

	h.Vulns = nil
	rr = httptest.NewRecorder()
	h.FeaturesHandler(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &f))
	require.False(t, f.Vulnerabilities)
}

// The literal segments (profiles, feeds) must not collide with {env}
// patterns; http.ServeMux panics on registration if they do.
func TestVulnRoutePatternsDoNotConflict(t *testing.T) {
	mux := http.NewServeMux()
	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	for _, p := range []string{
		"GET /api/v1/vulnerabilities/profiles",
		"GET /api/v1/vulnerabilities/feeds",
		"POST /api/v1/vulnerabilities/feeds/sync",
		"GET /api/v1/vulnerabilities/{env}/findings",
		"GET /api/v1/vulnerabilities/{env}/summary",
		"GET /api/v1/vulnerabilities/{env}/advisories/{id}",
		"GET /api/v1/nodes/{env}/node/{uuid}/vulnerabilities",
	} {
		require.NotPanics(t, func() { mux.Handle(p, noop) }, p)
	}
}
