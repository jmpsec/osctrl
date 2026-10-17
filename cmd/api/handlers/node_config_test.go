package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const nodeConfigEnvA = `{"options":{"verbose":false,"host_identifier":"uuid"},"schedule":{}}`

func setupNodeConfigHandlers(t *testing.T) (*HandlersApi, *gorm.DB, environments.TLSEnvironment, environments.TLSEnvironment, *nodeconfig.Manager) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesmgr := nodes.CreateNodes(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	mgr, err := nodeconfig.NewManager(db, nil)
	require.NoError(t, err)

	envA := environments.TLSEnvironment{UUID: "env-a", Name: "a", Configuration: nodeConfigEnvA}
	envB := environments.TLSEnvironment{UUID: "env-b", Name: "b", Configuration: "{}"}
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

	h := CreateHandlersApi(
		WithDB(db), WithEnvs(envs), WithUsers(userManager), WithNodes(nodesmgr),
		WithAuditLog(auditLog), WithNodeConfig(mgr), WithDebugHTTP(&config.YAMLConfigurationDebug{}),
	)
	return h, db, envA, envB, mgr
}

func nodeConfigRequest(method, user, env, node, body string) *http.Request {
	req := httptest.NewRequest(method, "/api/v1/nodes/"+env+"/node/"+node+"/config", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("env", env)
	req.SetPathValue("uuid", node)
	return req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
}

func serveNodeConfig(t *testing.T, h *HandlersApi, method, user, env, node, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := nodeConfigRequest(method, user, env, node, body)
	switch method {
	case http.MethodGet:
		h.NodeConfigGetHandler(rr, req)
	case http.MethodPut:
		h.NodeConfigPutHandler(rr, req)
	case http.MethodDelete:
		h.NodeConfigDeleteHandler(rr, req)
	default:
		t.Fatalf("unexpected method %s", method)
	}
	return rr
}

func decodeNodeConfig(t *testing.T, rr *httptest.ResponseRecorder) types.NodeConfigResponse {
	t.Helper()
	var resp types.NodeConfigResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp), rr.Body.String())
	return resp
}

func putBody(t *testing.T, override string, expires *time.Time) string {
	t.Helper()
	raw, err := json.Marshal(types.NodeConfigRequest{Override: override, ExpiresAt: expires})
	require.NoError(t, err)
	return string(raw)
}

func auditLines(t *testing.T, db *gorm.DB, logType uint, envID uint) []string {
	t.Helper()
	var rows []auditlog.AuditLog
	require.NoError(t, db.Where("log_type = ? AND environment_id = ?", logType, envID).Order("id").Find(&rows).Error)
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.Line
	}
	return lines
}

func TestNodeConfigPermissions(t *testing.T) {
	h, db, envA, envB, _ := setupNodeConfigHandlers(t)

	rr := serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	cases := []struct {
		user, env, node, method, body string
		envID                         uint
	}{
		{"alice", envB.Name, "NODE-B", http.MethodGet, "", envB.ID},
		{"bob", envA.Name, "NODE-A", http.MethodGet, "", envA.ID},
		{"bob", envA.Name, "NODE-A", http.MethodPut, putBody(t, `{"options":{"verbose":true}}`, nil), envA.ID},
		{"bob", envA.Name, "NODE-A", http.MethodDelete, "", envA.ID},
	}
	for _, c := range cases {
		before := len(auditLines(t, db, auditlog.LogTypeEnvironment, c.envID))
		rr := serveNodeConfig(t, h, c.method, c.user, c.env, c.node, c.body)
		require.Equal(t, http.StatusForbidden, rr.Code, "%s %s %s", c.method, c.user, c.env)
		lines := auditLines(t, db, auditlog.LogTypeEnvironment, c.envID)
		require.Len(t, lines, before+1, "%s %s %s", c.method, c.user, c.env)
		require.Contains(t, lines[len(lines)-1], "denied access for user "+c.user)
	}
	o, err := h.NodeConfig.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o, "denied PUT must not store anything")

	rr = serveNodeConfig(t, h, http.MethodGet, "root", envB.Name, "NODE-B", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestNodeConfigPutAndGet(t *testing.T) {
	h, _, envA, _, _ := setupNodeConfigHandlers(t)
	override := `{"options":{"verbose":true}}`
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, override, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	put := decodeNodeConfig(t, rr)
	require.Equal(t, override, put.Override)

	rr = serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeConfig(t, rr)
	want, err := nodeconfig.Merge(nodeConfigEnvA, override)
	require.NoError(t, err)
	require.Equal(t, nodeConfigEnvA, got.Environment)
	require.Equal(t, override, got.Override)
	require.Equal(t, want, got.Applied)
	require.Contains(t, got.Applied, `"verbose": true`)
	require.Contains(t, got.Applied, `"host_identifier": "uuid"`)
	require.Equal(t, "alice", got.UpdatedBy)
	require.False(t, got.Expired)
	require.Nil(t, got.ExpiresAt)
	require.NotNil(t, got.UpdatedAt)
}

func TestNodeConfigPutRefusesProtectedAndNull(t *testing.T) {
	h, _, envA, _, mgr := setupNodeConfigHandlers(t)
	for override, key := range map[string]string{
		`{"options":{"config_tls_endpoint":"/x"}}`: "config_tls_endpoint",
		`{"schedule":{"q":null}}`:                  "schedule.q",
	} {
		rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, override, nil))
		require.Equal(t, http.StatusBadRequest, rr.Code, override)
		require.Contains(t, rr.Body.String(), key)
		o, err := mgr.Get("NODE-A")
		require.NoError(t, err)
		require.Nil(t, o, override)
	}
}

func TestNodeConfigPutRefusesPastExpiry(t *testing.T) {
	h, _, envA, _, mgr := setupNodeConfigHandlers(t)
	past := time.Now().Add(-time.Minute)
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, `{"options":{"verbose":true}}`, &past))
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	o, err := mgr.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o)
}

func TestNodeConfigPutRefusesOversizedBody(t *testing.T) {
	h, _, envA, _, mgr := setupNodeConfigHandlers(t)
	big := `{"options":{"verbose":true},"decorators":{"always":["` + strings.Repeat("a", 300<<10) + `"]}}`
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, big, nil))
	require.GreaterOrEqual(t, rr.Code, 400)
	require.Less(t, rr.Code, 500)
	o, err := mgr.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o)
}

func TestNodeConfigKeysByNodeRowUUID(t *testing.T) {
	h, db, envA, _, mgr := setupNodeConfigHandlers(t)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "ABC-UPPER", EnvironmentID: envA.ID, Environment: envA.Name}).Error)
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "abc-upper", putBody(t, `{"options":{"verbose":true}}`, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	o, err := mgr.Get("ABC-UPPER")
	require.NoError(t, err)
	require.NotNil(t, o)
	require.Equal(t, envA.ID, o.EnvironmentID)
	lower, err := mgr.Get("abc-upper")
	require.NoError(t, err)
	require.Nil(t, lower)
}

func TestNodeConfigExpiredReportedNotApplied(t *testing.T) {
	h, db, envA, _, _ := setupNodeConfigHandlers(t)
	past := time.Now().Add(-time.Hour)
	override := `{"options":{"verbose":true}}`
	require.NoError(t, db.Create(&nodeconfig.Override{NodeUUID: "NODE-A", EnvironmentID: envA.ID, Config: override, ExpiresAt: &past, UpdatedBy: "alice"}).Error)

	rr := serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeConfig(t, rr)
	require.True(t, got.Expired)
	require.Equal(t, got.Environment, got.Applied)
	require.Equal(t, override, got.Override)
	require.NotNil(t, got.ExpiresAt)
}

func TestNodeConfigDelete(t *testing.T) {
	h, db, envA, _, mgr := setupNodeConfigHandlers(t)
	override := `{"options":{"verbose":true}}`
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, override, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = serveNodeConfig(t, h, http.MethodDelete, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	del := decodeNodeConfig(t, rr)
	require.Empty(t, del.Override)

	rr = serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeConfig(t, rr)
	require.Empty(t, got.Override)
	require.Equal(t, got.Environment, got.Applied)
	o, err := mgr.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o)

	lines := auditLines(t, db, auditlog.LogTypeNode, envA.ID)
	require.NotEmpty(t, lines)
	require.Contains(t, lines[len(lines)-1], "removed config override on node NODE-A: before="+override)
}

func TestNodeConfigAudited(t *testing.T) {
	h, db, envA, _, _ := setupNodeConfigHandlers(t)
	override := `{"options":{"verbose":true}}`
	rr := serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, override, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	lines := auditLines(t, db, auditlog.LogTypeNode, envA.ID)
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "set config override on node NODE-A (expires never): before=none after="+override)

	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rr = serveNodeConfig(t, h, http.MethodPut, "alice", envA.Name, "NODE-A", putBody(t, `{"options":{"verbose":false}}`, &expires))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	lines = auditLines(t, db, auditlog.LogTypeNode, envA.ID)
	require.Len(t, lines, 2)
	require.Contains(t, lines[1], "(expires "+expires.Format(time.RFC3339)+"): before="+override+` after={"options":{"verbose":false}}`)
}

func TestDeleteNodeRemovesOverride(t *testing.T) {
	h, _, envA, _, mgr := setupNodeConfigHandlers(t)
	_, err := mgr.Set(context.Background(), nodeconfig.Override{NodeUUID: "NODE-A", EnvironmentID: envA.ID, Config: `{"options":{"verbose":true}}`})
	require.NoError(t, err)

	body, err := json.Marshal(types.ApiNodeGenericRequest{UUID: "NODE-A"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/a/delete", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("env", envA.Name)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"}))
	rr := httptest.NewRecorder()
	h.DeleteNodeHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	o, err := mgr.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o)
}

func TestNodeConfigIgnoresHostnameDecoy(t *testing.T) {
	h, db, envA, _, mgr := setupNodeConfigHandlers(t)
	// The decoy reports the target's UUID as its hostname and has the lower row ID.
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "DECOY-UUID", Hostname: "TARGET-UUID", Localname: "decoy-local", EnvironmentID: envA.ID, Environment: envA.Name}).Error)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "TARGET-UUID", EnvironmentID: envA.ID, Environment: envA.Name}).Error)
	for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodDelete} {
		if method == http.MethodDelete {
			_, err := mgr.Set(context.Background(), nodeconfig.Override{NodeUUID: "DECOY-UUID", EnvironmentID: envA.ID, Config: `{"options":{"verbose":false}}`})
			require.NoError(t, err)
		}
		rr := serveNodeConfig(t, h, method, "alice", envA.Name, "TARGET-UUID", putBody(t, `{"options":{"verbose":true}}`, nil))
		require.Equal(t, http.StatusOK, rr.Code, "%s %s", method, rr.Body.String())
		switch method {
		case http.MethodPut:
			o, err := mgr.Get("TARGET-UUID")
			require.NoError(t, err)
			require.NotNil(t, o)
			decoy, err := mgr.Get("DECOY-UUID")
			require.NoError(t, err)
			require.Nil(t, decoy)
		case http.MethodGet:
			require.Equal(t, `{"options":{"verbose":true}}`, decodeNodeConfig(t, rr).Override)
		case http.MethodDelete:
			decoy, err := mgr.Get("DECOY-UUID")
			require.NoError(t, err)
			require.NotNil(t, decoy, "DELETE must not remove the decoy's override")
		}
	}
	// Hostnames and local names are not accepted as node identifiers.
	rr := serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "decoy-local", "")
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestNodeConfigCrossEnvNodeNotFound(t *testing.T) {
	h, _, envA, envB, mgr := setupNodeConfigHandlers(t)
	const existing = `{"options":{"verbose":false}}`
	_, err := mgr.Set(context.Background(), nodeconfig.Override{NodeUUID: "NODE-B", EnvironmentID: envB.ID, Config: existing})
	require.NoError(t, err)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rr := serveNodeConfig(t, h, method, "alice", envA.Name, "NODE-B", putBody(t, `{"options":{"verbose":true}}`, nil))
		require.Equal(t, http.StatusNotFound, rr.Code, method)
		o, err := mgr.Get("NODE-B")
		require.NoError(t, err)
		require.NotNil(t, o, method)
		require.Equal(t, existing, o.Config, method)
		require.Equal(t, envB.ID, o.EnvironmentID, method)
	}
}

func TestNodeConfigOtherEnvRowNotReported(t *testing.T) {
	h, db, envA, envB, _ := setupNodeConfigHandlers(t)
	require.NoError(t, db.Create(&nodeconfig.Override{NodeUUID: "NODE-A", EnvironmentID: envB.ID, Config: `{"options":{"verbose":true}}`, UpdatedBy: "root"}).Error)
	rr := serveNodeConfig(t, h, http.MethodGet, "alice", envA.Name, "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeConfig(t, rr)
	require.Empty(t, got.Override)
	require.Empty(t, got.UpdatedBy)
	require.Equal(t, nodeConfigEnvA, got.Applied)
	require.Equal(t, got.Environment, got.Applied)
}
