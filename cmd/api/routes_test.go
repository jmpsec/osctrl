package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/jmpsec/osctrl/pkg/users"
)

const routeTestSecret = "route-test-secret-at-least-thirty-two-bytes"

// routeTestParams turns on every conditionally registered route group, so a
// pattern conflict anywhere in the production route set panics here.
func routeTestParams(mcp *config.YAMLConfigurationMCP) *config.ServiceParameters {
	return &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{
			Auth:                 config.AuthJWT,
			AuditLog:             true,
			HealthEnabled:        true,
			PostureEnabled:       true,
			ServiceConfigEnabled: true,
			VulnEnabled:          true,
		},
		JWT:        &config.YAMLConfigurationJWT{JWTSecret: routeTestSecret},
		Osquery:    &config.YAMLConfigurationOsquery{Query: true, Carve: true, Console: true, FileExplorer: true},
		OIDC:       &config.YAMLConfigurationOIDC{Enabled: true},
		SAML:       &config.YAMLConfigurationSAML{Enabled: true},
		RateLimits: config.DefaultRateLimitsPtr(),
		MCP:        mcp,
	}
}

func newRouteTestMux(t *testing.T, h *handlers.HandlersApi, mcp *config.YAMLConfigurationMCP) *http.ServeMux {
	t.Helper()
	if h == nil {
		h = &handlers.HandlersApi{}
	}
	if h.DebugHTTPConfig == nil {
		h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	}
	mux := http.NewServeMux()
	registerRoutes(mux, h, routeTestParams(mcp), &events.Bus{}, &alerts.Manager{}, true, true, &fakeAuditLog{})
	return mux
}

func serveRoute(mux http.Handler, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// Regression for #1099: a methodless /api/v1/mcp pattern conflicts with
// "GET /" and panicked osctrl-api at startup whenever MCP was enabled.
func TestRegisterRoutesAllEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		mcp  *config.YAMLConfigurationMCP
	}{
		{"mcp unset", nil},
		{"mcp disabled", &config.YAMLConfigurationMCP{}},
		{"mcp read-only", &config.YAMLConfigurationMCP{Enabled: true}},
		{"mcp writes", &config.YAMLConfigurationMCP{Enabled: true, AllowWrites: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() { newRouteTestMux(t, nil, tc.mcp) })
		})
	}
}

func TestRegisterRoutesMCPEndpoint(t *testing.T) {
	mcpPath := _apiPath(apiMCPPath)

	t.Run("disabled falls through to the root handler", func(t *testing.T) {
		mux := newRouteTestMux(t, nil, &config.YAMLConfigurationMCP{})
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, mcpPath, nil))
		require.Equal(t, "GET /", pattern)
		require.Equal(t, http.StatusNotFound, serveRoute(mux, http.MethodGet, mcpPath).Code)
		require.Equal(t, http.StatusMethodNotAllowed, serveRoute(mux, http.MethodPost, mcpPath).Code)
	})

	for _, allowWrites := range []bool{false, true} {
		mux := newRouteTestMux(t, nil, &config.YAMLConfigurationMCP{Enabled: true, AllowWrites: allowWrites})
		for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
			_, pattern := mux.Handler(httptest.NewRequest(method, mcpPath, nil))
			require.Equal(t, method+" "+mcpPath, pattern)
			// No token: handlerAuthCheck rejects before the MCP handler runs.
			require.Equal(t, http.StatusUnauthorized, serveRoute(mux, method, mcpPath).Code, method)
		}
		// HEAD rides the GET pattern, so it is still auth-gated.
		require.Equal(t, http.StatusUnauthorized, serveRoute(mux, http.MethodHead, mcpPath).Code)
		for _, method := range []string{http.MethodPut, http.MethodPatch} {
			require.Equal(t, http.StatusMethodNotAllowed, serveRoute(mux, method, mcpPath).Code, method)
		}
	}
}

// The extraction from osctrlAPIService must keep every registration.
func TestRegisterRoutesKeepsExistingRoutes(t *testing.T) {
	mux := newRouteTestMux(t, nil, &config.YAMLConfigurationMCP{Enabled: true})
	for _, tc := range []struct{ method, path, pattern string }{
		{http.MethodGet, "/", "GET /"},
		{http.MethodGet, healthPath, "GET " + healthPath},
		{http.MethodPost, _apiPath(apiLoginPath), "POST " + _apiPath(apiLoginPath)},
		{http.MethodGet, "/api/v1/events", "GET /api/v1/events"},
		{http.MethodGet, _apiPath(apiNodesPath) + "/dev/all", "GET " + _apiPath(apiNodesPath) + "/{env}/all"},
		{http.MethodGet, _apiPath(apiAuthPath) + "/oidc/login", "GET " + _apiPath(apiAuthPath) + "/oidc/login"},
		{http.MethodPost, _apiPath(apiAuthPath) + "/saml/acs", "POST " + _apiPath(apiAuthPath) + "/saml/acs"},
		{http.MethodGet, _apiPath(apiAuditLogsPath), "GET " + _apiPath(apiAuditLogsPath)},
		{http.MethodGet, _apiPath(apiAlertsPath) + "/rules", "GET " + _apiPath(apiAlertsPath) + "/rules"},
		{http.MethodGet, _apiPath(apiLogSinksPath), "GET " + _apiPath(apiLogSinksPath)},
		{http.MethodGet, _apiPath(apiAuthProvidersPath), "GET " + _apiPath(apiAuthProvidersPath)},
	} {
		_, pattern := mux.Handler(httptest.NewRequest(tc.method, tc.path, nil))
		require.Equal(t, tc.pattern, pattern, tc.method+" "+tc.path)
	}
	require.Equal(t, http.StatusOK, serveRoute(mux, http.MethodGet, "/").Code)
	require.Equal(t, http.StatusOK, serveRoute(mux, http.MethodGet, healthPath).Code)
	require.Equal(t, http.StatusUnauthorized, serveRoute(mux, http.MethodGet, "/api/v1/events").Code)
	require.Equal(t, http.StatusUnauthorized, serveRoute(mux, http.MethodGet, _apiPath(apiNodesPath)+"/dev/all").Code)
}

// An authenticated client completes the MCP handshake through the real mux,
// and a tool call loops back into that same mux as the caller.
func TestRegisterRoutesMCPRoundTrip(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	// Registered first so it runs last; closing drops the shared-cache DB so
	// a repeat run (-count=N) starts empty.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	previous := apiUsers
	t.Cleanup(func() { apiUsers = previous })
	apiUsers = users.CreateUserManager(db).WithJWT(&config.YAMLConfigurationJWT{JWTSecret: routeTestSecret, HoursToExpire: 1})
	require.NoError(t, apiUsers.Create(users.AdminUser{Username: "alice", Admin: true}))
	token, expiry, err := apiUsers.CreateToken("alice", "api", 1)
	require.NoError(t, err)
	require.NoError(t, apiUsers.UpdateToken("alice", token, expiry))
	envs := environments.CreateEnvironment(db)
	require.NoError(t, db.Create(&environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "dev"}).Error)

	mux := newRouteTestMux(t, &handlers.HandlersApi{Users: apiUsers, Envs: envs}, &config.YAMLConfigurationMCP{Enabled: true})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint: srv.URL + _apiPath(apiMCPPath),
		HTTPClient: &http.Client{Transport: headerInjector{apply: func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
		}}},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{Name: "list_environments"})
	require.NoError(t, err)
	require.False(t, res.IsError)
	out, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	require.Contains(t, string(out), `"name":"dev"`)

	// POST, GET and DELETE must share one handler: the session created by
	// the POST above has to be visible to a DELETE on the same path.
	del, err := http.NewRequest(http.MethodDelete, srv.URL+_apiPath(apiMCPPath), nil)
	require.NoError(t, err)
	del.Header.Set("Authorization", "Bearer "+token)
	del.Header.Set("Mcp-Session-Id", session.ID())
	resp, err := http.DefaultClient.Do(del)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
}
