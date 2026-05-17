package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
)

// TestAuthMethodsPasswordOnly asserts the default branch: when
// OIDCEnabled is false, the response advertises only the password
// method. The SPA uses this exact shape to decide whether to render
// the "Continue with SSO" button — if a future refactor accidentally
// returns OIDC even when disabled, the SPA would link a button to a
// 404 route. Catch that here.
func TestAuthMethodsPasswordOnly(t *testing.T) {
	h := &HandlersApi{
		OIDCEnabled:     false,
		DebugHTTPConfig: &config.YAMLConfigurationDebug{}, // EnableHTTP=false
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	w := httptest.NewRecorder()

	h.AuthMethodsHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp AuthMethodsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if len(resp.Methods) != 1 {
		t.Fatalf("methods len: got %d want 1 (body=%s)", len(resp.Methods), w.Body.String())
	}
	if resp.Methods[0].Type != "password" {
		t.Errorf("methods[0].type: got %q want %q", resp.Methods[0].Type, "password")
	}
	if resp.Methods[0].LoginURL != "/api/v1/login" {
		t.Errorf("methods[0].loginUrl: got %q want %q", resp.Methods[0].LoginURL, "/api/v1/login")
	}
}

// TestAuthMethodsWithOIDC asserts that flipping OIDCEnabled to true
// appends an "oidc" method with the correct global login URL. The URL
// matches the route registered in cmd/api/main.go; if the constant
// drifts, this test catches it before a deployed SPA does.
func TestAuthMethodsWithOIDC(t *testing.T) {
	h := &HandlersApi{
		OIDCEnabled:     true,
		DebugHTTPConfig: &config.YAMLConfigurationDebug{},
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	w := httptest.NewRecorder()

	h.AuthMethodsHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", w.Code)
	}
	var resp AuthMethodsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Methods) != 2 {
		t.Fatalf("methods len: got %d want 2 (body=%s)", len(resp.Methods), w.Body.String())
	}
	if resp.Methods[0].Type != "password" {
		t.Errorf("methods[0].type: got %q want %q (password must come first)", resp.Methods[0].Type, "password")
	}
	if resp.Methods[1].Type != "oidc" {
		t.Errorf("methods[1].type: got %q want %q", resp.Methods[1].Type, "oidc")
	}
	if resp.Methods[1].LoginURL != "/api/v1/auth/oidc/login" {
		t.Errorf("methods[1].loginUrl: got %q want %q", resp.Methods[1].LoginURL, "/api/v1/auth/oidc/login")
	}
}

// TestAuthMethodsContentType ensures the response advertises
// application/json so SPA-side fetch wrappers select the JSON
// decoder path. Cheap regression guard.
func TestAuthMethodsContentType(t *testing.T) {
	h := &HandlersApi{DebugHTTPConfig: &config.YAMLConfigurationDebug{}}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/methods", nil)
	w := httptest.NewRecorder()

	h.AuthMethodsHandler(w, r)

	got := w.Header().Get("Content-Type")
	if got == "" {
		t.Fatalf("missing Content-Type header")
	}
	// HTTPResponse uses "application/json; charset=UTF-8". Allow any
	// content-type that mentions application/json so future header
	// nuance doesn't break the test.
	if !contains(got, "application/json") {
		t.Errorf("Content-Type: got %q want substring application/json", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
