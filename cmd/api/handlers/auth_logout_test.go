package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
)

// TestLogoutAnonymousHidesIdPMetadata is the regression for the
// pentest finding: an unauthenticated caller hitting POST /logout
// MUST NOT receive the IdPLogoutURL / IdPClientID / IdPIDTokenHint
// fields, even when an OIDC provider is configured on the api. Those
// fields exist to support the SPA's "click logout → redirect to IdP's
// /v1/logout" flow; surfacing them to anonymous callers lets a
// drive-by curl harvest the tenant URL and OIDC client_id.
func TestLogoutAnonymousHidesIdPMetadata(t *testing.T) {
	// Stand up a fake IdP so we have a non-nil oidcProvider — without
	// that the test trivially passes because the gate is also "is
	// oidcProvider configured?".
	idp := newFakeIdP(t)
	initOIDCWithFake(t, idp, false)

	// Mirror the package globals InitOIDC populates.
	prevClientID := oidcClientID
	t.Cleanup(func() { oidcClientID = prevClientID })
	oidcClientID = "osctrl-api-test"

	h := &HandlersApi{
		DebugHTTPConfig: &config.YAMLConfigurationDebug{},
		JWTSecret:       []byte("test-jwt-secret-must-be-at-least-32-bytes-long"),
		OIDCEnabled:     true,
	}

	// No cookies. Anonymous request.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	w := httptest.NewRecorder()

	h.LogoutHandler(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent logout, got %d", w.Code)
	}

	var resp LogoutResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.IdPLogoutURL != "" {
		t.Errorf("anonymous /logout must not leak IdPLogoutURL, got %q", resp.IdPLogoutURL)
	}
	if resp.IdPClientID != "" {
		t.Errorf("anonymous /logout must not leak IdPClientID, got %q", resp.IdPClientID)
	}
	if resp.IdPIDTokenHint != "" {
		t.Errorf("anonymous /logout must not leak IdPIDTokenHint, got %q", resp.IdPIDTokenHint)
	}
}

// TestLogoutClearsCookiesEvenWhenAnonymous confirms the idempotent
// contract: anonymous /logout still emits cookie-clearing Set-Cookie
// headers so a stale cookie that survived a backend restart gets
// purged on next logout click.
func TestLogoutClearsCookiesEvenWhenAnonymous(t *testing.T) {
	h := &HandlersApi{
		DebugHTTPConfig: &config.YAMLConfigurationDebug{},
		JWTSecret:       []byte("test-jwt-secret-must-be-at-least-32-bytes-long"),
	}

	r := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	w := httptest.NewRecorder()
	h.LogoutHandler(w, r)

	cookies := w.Result().Cookies()
	got := map[string]bool{}
	for _, c := range cookies {
		if c.MaxAge < 0 {
			got[c.Name] = true
		}
	}
	for _, want := range []string{"osctrl_token", "osctrl_csrf", "osctrl_id_token"} {
		if !got[want] {
			t.Errorf("anonymous logout did not clear cookie %q", want)
		}
	}
}
