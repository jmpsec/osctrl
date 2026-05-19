package saml

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auth"
)

// minimalIDPMetadata is enough XML for NewSAMLProvider's metadata parse
// to succeed without going through crewjam's cert/key parsing path.
// The contents intentionally lack signing keys — the unit tests in this
// file cover the protocol-neutral logic (state cookie binding,
// AuthnRequest URL shape, error mapping). Signed-assertion roundtrips
// are the responsibility of the live pentest against Keycloak/Auth0.
const minimalIDPMetadata = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="http://idp.example.com/realms/test">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="http://idp.example.com/realms/test/protocol/saml"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func testProvider(t *testing.T) *Provider {
	t.Helper()
	cfg := Config{
		IDPMetadataXML:         minimalIDPMetadata,
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	p, err := NewSAMLProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewSAMLProvider: %v", err)
	}
	return p
}

func TestNewSAMLProvider_RejectsInvalidConfig(t *testing.T) {
	_, err := NewSAMLProvider(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected validation error on zero config")
	}
}

func TestProvider_TypeIsSAML(t *testing.T) {
	p := testProvider(t)
	if got := p.Type(); got != auth.TypeSAML {
		t.Errorf("Type: got %q want %q", got, auth.TypeSAML)
	}
}

func TestProvider_MetadataParses(t *testing.T) {
	p := testProvider(t)
	md, err := p.Metadata()
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	if !strings.Contains(string(md), "EntityDescriptor") {
		t.Errorf("metadata should contain EntityDescriptor, got: %s", string(md)[:min(200, len(md))])
	}
	if !strings.Contains(string(md), "http://sp.example.com/saml/metadata") {
		t.Errorf("metadata should contain SP entityID")
	}
}

func TestProvider_LoginURL_HappyPath(t *testing.T) {
	p := testProvider(t)
	got, err := p.LoginURL(context.Background(), auth.State{
		EnvUUID:    "global",
		Nonce:      "n-test-32-bytes-of-entropy",
		OAuthState: "s-test-32-bytes-of-entropy",
	})
	if err != nil {
		t.Fatalf("LoginURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("LoginURL not a valid URL: %v", err)
	}
	if !strings.HasPrefix(got, "http://idp.example.com/realms/test/protocol/saml?") {
		t.Errorf("LoginURL should target IdP SSO endpoint, got %s", got)
	}
	// SAMLRequest must be present (the encoded AuthnRequest).
	if u.Query().Get("SAMLRequest") == "" {
		t.Errorf("LoginURL missing SAMLRequest param: %s", got)
	}
	// RelayState must echo OAuthState (NOT Nonce — May 2026 split).
	if got := u.Query().Get("RelayState"); got != "s-test-32-bytes-of-entropy" {
		t.Errorf("RelayState should equal OAuthState, got %q", got)
	}
}

func TestProvider_LoginURL_RejectsEmptyEnv(t *testing.T) {
	p := testProvider(t)
	_, err := p.LoginURL(context.Background(), auth.State{OAuthState: "s-x"})
	if err == nil {
		t.Fatal("empty EnvUUID should error")
	}
}

func TestProvider_LoginURL_RejectsEmptyOAuthState(t *testing.T) {
	p := testProvider(t)
	_, err := p.LoginURL(context.Background(), auth.State{EnvUUID: "global"})
	if err == nil {
		t.Fatal("empty OAuthState should error")
	}
}

// TestHandleCallback_StateMismatch covers threat S10 (RelayState
// injection). An attacker who triggers a callback with a SAMLResponse
// but no/wrong RelayState must be rejected BEFORE any crypto parsing.
func TestHandleCallback_StateMismatch(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("SAMLResponse", "ignored-not-yet-parsed")
	form.Set("RelayState", "attacker-supplied-value")
	r := httptest.NewRequest("POST", "http://sp.example.com/saml/acs",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.HandleCallback(context.Background(), r,
		auth.State{EnvUUID: "global", Nonce: "n-the-real-nonce", OAuthState: "the-real-nonce"})
	if err != ErrStateMismatch {
		t.Errorf("expected ErrStateMismatch, got %v", err)
	}
}

// TestHandleCallback_MissingSAMLResponse — POST without a SAMLResponse
// field is rejected immediately, NOT bubbled up to a confusing crewjam
// XML parse error.
func TestHandleCallback_MissingSAMLResponse(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("RelayState", "the-real-nonce")
	r := httptest.NewRequest("POST", "http://sp.example.com/saml/acs",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.HandleCallback(context.Background(), r,
		auth.State{EnvUUID: "global", Nonce: "n-the-real-nonce", OAuthState: "the-real-nonce"})
	if err != ErrMissingSAMLResponse {
		t.Errorf("expected ErrMissingSAMLResponse, got %v", err)
	}
}

// TestHandleCallback_GarbageSAMLResponse — RelayState matches, but the
// SAMLResponse body is not parseable XML. Should map to ErrParseResponse
// rather than panicking or leaking internal error text to the caller.
func TestHandleCallback_GarbageSAMLResponse(t *testing.T) {
	p := testProvider(t)

	form := url.Values{}
	form.Set("SAMLResponse", "this-is-not-base64-saml")
	form.Set("RelayState", "the-real-nonce")
	r := httptest.NewRequest("POST", "http://sp.example.com/saml/acs",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.HandleCallback(context.Background(), r,
		auth.State{EnvUUID: "global", Nonce: "n-the-real-nonce", OAuthState: "the-real-nonce"})
	if err == nil {
		t.Fatal("garbage SAMLResponse should error")
	}
	if !errIs(err, ErrParseResponse) {
		t.Errorf("expected ErrParseResponse wrap, got %v", err)
	}
}

// TestParseMetadataXML_EntitiesDescriptorFallback covers the real-world
// case where the IdP emits <EntitiesDescriptor><EntityDescriptor/></...>
// (Shibboleth, ADFS, federation metadata). The parser tries
// EntityDescriptor first and falls back to EntitiesDescriptor.
func TestParseMetadataXML_EntitiesDescriptorFallback(t *testing.T) {
	xml := `<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="http://wrapped-idp.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                           Location="http://wrapped-idp.example.com/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`
	ed, err := parseMetadataXML([]byte(xml))
	if err != nil {
		t.Fatalf("EntitiesDescriptor fallback failed: %v", err)
	}
	if ed.EntityID != "http://wrapped-idp.example.com" {
		t.Errorf("entityID: got %q want http://wrapped-idp.example.com", ed.EntityID)
	}
}

func TestFetchIDPMetadata_HTTPSurface(t *testing.T) {
	// Run a tiny in-process metadata server so we exercise the
	// fetcher without depending on a real IdP being reachable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write([]byte(minimalIDPMetadata))
	}))
	defer srv.Close()

	cfg := Config{
		IDPMetadataURL:         srv.URL,
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	if _, err := NewSAMLProvider(context.Background(), cfg); err != nil {
		t.Fatalf("HTTP metadata fetch failed: %v", err)
	}
}

func TestFetchIDPMetadata_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := Config{
		IDPMetadataURL:         srv.URL,
		EntityID:               "http://sp.example.com/saml/metadata",
		ACSURL:                 "http://sp.example.com/saml/acs",
		RequireAssertionSigned: true,
	}
	if _, err := NewSAMLProvider(context.Background(), cfg); err == nil {
		t.Fatal("expected error on 503 metadata response")
	}
}

func errIs(got, target error) bool {
	if got == nil {
		return false
	}
	if got == target {
		return true
	}
	// fmt.Errorf("%w: ...", target) wraps the sentinel.
	return strings.Contains(got.Error(), target.Error())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
