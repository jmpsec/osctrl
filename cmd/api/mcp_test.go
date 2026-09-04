package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// The hosted MCP server deliberately owns no authorization logic: every tool
// call is dispatched back through osctrl-api's own mux so the real handler
// chain decides. These tests pin the two properties that makes it safe —
// the caller's credentials reach the handler, and the handler's verdict
// reaches the MCP client.

// recordingAPI stands in for the API mux. It records the last request it saw
// and serves whatever the test configures.
type recordingAPI struct {
	gotAuth       string
	gotCookies    []*http.Cookie
	gotRemoteAddr string
	gotUserAgent  string
	gotPath       string
	status        int
	body          string
}

func (a *recordingAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.gotAuth = r.Header.Get("Authorization")
	a.gotCookies = r.Cookies()
	a.gotRemoteAddr = r.RemoteAddr
	a.gotUserAgent = r.Header.Get("User-Agent")
	a.gotPath = r.URL.Path
	if a.status == 0 {
		a.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(a.status)
	_, _ = w.Write([]byte(a.body))
}

// newMCPClient mounts mcpHandler over api and returns a connected MCP session.
// creds are applied to the inbound HTTP request the way a real client would.
func newMCPClient(t *testing.T, api http.Handler, apply func(*http.Request)) *sdk.ClientSession {
	t.Helper()
	srv := httptest.NewServer(mcpHandler(api, "test"))
	t.Cleanup(srv.Close)

	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint:   srv.URL,
		HTTPClient: &http.Client{Transport: headerInjector{apply: apply}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// headerInjector applies the test's credentials to every outbound request.
type headerInjector struct{ apply func(*http.Request) }

func (h headerInjector) RoundTrip(r *http.Request) (*http.Response, error) {
	if h.apply != nil {
		h.apply(r)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestLoopbackTransportPropagatesCaller(t *testing.T) {
	api := &recordingAPI{body: `[]`}
	session := newMCPClient(t, api, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer caller-token")
		r.Header.Set("User-Agent", "mcp-client/1.0")
		r.AddCookie(&http.Cookie{Name: "osctrl_token", Value: "cookie-value"})
	})

	if _, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "list_environments", Arguments: map[string]any{},
	}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	// The handler must authenticate as the caller, not as the service.
	if api.gotAuth != "Bearer caller-token" {
		t.Errorf("Authorization = %q, want the caller's bearer token", api.gotAuth)
	}
	if len(api.gotCookies) != 1 || api.gotCookies[0].Value != "cookie-value" {
		t.Errorf("cookies = %+v, want the caller's session cookie", api.gotCookies)
	}
	// Audit entries and rate-limit buckets must attribute to the real client.
	if api.gotRemoteAddr == "" {
		t.Error("RemoteAddr not propagated — audit logs would attribute to the server")
	}
	if api.gotUserAgent != "mcp-client/1.0" {
		t.Errorf("User-Agent = %q, want the caller's", api.gotUserAgent)
	}
	if api.gotPath != "/api/v1/environments" {
		t.Errorf("dispatched to %q, want /api/v1/environments", api.gotPath)
	}
}

// The point of dispatching through the mux: whatever the handler decides
// about permissions is what the MCP client gets. A 403 must surface as a
// tool error, never as empty-but-successful data.
func TestHandlerDenialSurfacesAsToolError(t *testing.T) {
	api := &recordingAPI{status: http.StatusForbidden, body: `{"error":"no access"}`}
	session := newMCPClient(t, api, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer low-privilege")
	})

	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_node",
		Arguments: map[string]any{"environment": "prod", "identifier": "UUID1"},
	})
	if err == nil && !res.IsError {
		t.Fatal("a 403 from the handler chain must surface as a tool error, not as success")
	}
}

func TestToolDataRoundTripsThroughLoopback(t *testing.T) {
	api := &recordingAPI{body: `[{"uuid":"e1","name":"prod","hostname":"osctrl.example.com","type":"osquery","secret":"LEAKME"}]`}
	session := newMCPClient(t, api, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer token")
	})

	res, err := session.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "list_environments", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out struct {
		Environments []struct {
			Name string `json:"name"`
		} `json:"environments"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Environments) != 1 || out.Environments[0].Name != "prod" {
		t.Fatalf("unexpected environments: %s", raw)
	}
	// The projection still applies over the hosted transport.
	if string(raw) != "" && containsSecret(string(raw)) {
		t.Errorf("enrollment secret leaked through the hosted transport: %s", raw)
	}
}

func containsSecret(s string) bool {
	for i := 0; i+6 <= len(s); i++ {
		if s[i:i+6] == "LEAKME" {
			return true
		}
	}
	return false
}

// Each request builds its own server bound to that request's credentials, so
// two callers can never share an identity.
func TestPerRequestCredentialIsolation(t *testing.T) {
	api := &recordingAPI{body: `[]`}

	first := newMCPClient(t, api, func(r *http.Request) { r.Header.Set("Authorization", "Bearer alice") })
	if _, err := first.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "list_environments", Arguments: map[string]any{},
	}); err != nil {
		t.Fatalf("alice: %v", err)
	}
	if api.gotAuth != "Bearer alice" {
		t.Fatalf("Authorization = %q, want alice", api.gotAuth)
	}

	second := newMCPClient(t, api, func(r *http.Request) { r.Header.Set("Authorization", "Bearer bob") })
	if _, err := second.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "list_environments", Arguments: map[string]any{},
	}); err != nil {
		t.Fatalf("bob: %v", err)
	}
	if api.gotAuth != "Bearer bob" {
		t.Fatalf("Authorization = %q, want bob — a cached client leaked alice's identity", api.gotAuth)
	}
}
