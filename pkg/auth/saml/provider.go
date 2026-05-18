package saml

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	crewjam "github.com/crewjam/saml"
	"github.com/rs/zerolog/log"

	"github.com/jmpsec/osctrl/pkg/auth"
)

// httpMetadataTimeout caps how long the IdP metadata fetch may take.
// Independent of any caller context — startup must not hang on a slow
// IdP. The metadata is fetched once at NewSAMLProvider time and cached.
const httpMetadataTimeout = 30 * time.Second

// Errors returned by HandleCallback. Callers map these to HTTP status
// codes. Strings are stable across versions; logs may use them, but
// client responses should be a single generic "authentication failed"
// (timing-oracle defense, threat S1-related).
var (
	// ErrStateMismatch — the RelayState param the IdP echoed back
	// doesn't match the state cookie's nonce. Threat S10 (RelayState
	// injection) and the SAML analogue of OIDC CSRF.
	ErrStateMismatch = errors.New("saml: state mismatch")

	// ErrParseResponse wraps any failure in crewjam's ParseResponse —
	// signature verification, audience check, NotBefore/NotOnOrAfter,
	// InResponseTo, recipient. Threats S1, S2, S4, S5, S6, S7.
	ErrParseResponse = errors.New("saml: assertion validation failed")

	// ErrMissingSAMLResponse — the POST body has no SAMLResponse form
	// field. Most likely a misconfigured IdP or a stale link; reject
	// with a clean log.
	ErrMissingSAMLResponse = errors.New("saml: SAMLResponse missing from request")

	// ErrGroupNotAllowed — RequiredGroups gate denial. SAML equivalent
	// of OIDC's T17.
	ErrGroupNotAllowed = errors.New("saml: user not in required group")

	// ErrUsernameInvalid — sanitizeUsername rejected the resolved
	// username. Threats S-equivalent of T23 + audit-log poisoning.
	ErrUsernameInvalid = errors.New("saml: username failed character validation")

	// ErrReplay — the assertion's ID has been seen before within the
	// replay window. Threat S3 (assertion replay). The crewjam library
	// rejects expired assertions but not replayed-within-window ones;
	// we add a small in-memory ring buffer.
	ErrReplay = errors.New("saml: assertion replay detected")
)

// Provider is the concrete SAML 2.0 implementation of auth.Provider.
// Constructed once at startup, safe for concurrent use. The underlying
// crewjam ServiceProvider is configured during NewSAMLProvider; we
// never mutate its fields after construction.
type Provider struct {
	cfg Config
	sp  *crewjam.ServiceProvider

	// replayCache prevents assertion replay within the configured
	// window. crewjam's ParseResponse rejects assertions outside their
	// NotBefore/NotOnOrAfter window, but an attacker who captures a
	// freshly-issued assertion can replay it within that window. We
	// track every successfully-parsed assertion ID and reject repeats.
	replayCache *replayCache
}

// Compile-time check that Provider implements auth.Provider.
var _ auth.Provider = (*Provider)(nil)

// NewSAMLProvider constructs a Provider from the given Config. The
// context bounds the IdP-metadata fetch (when Config.IDPMetadataURL is
// set); pass a context with a deadline so a hung IdP at init time
// doesn't wedge startup.
//
// Returns a non-nil error and a nil Provider on:
//   - Config validation failure
//   - IdP metadata fetch / parse failure
//   - SP URL parse failure
//
// The returned Provider's ServiceProvider is configured to require
// signed assertions (S2 defense) and the default crewjam clock-skew
// allowance.
func NewSAMLProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("saml: parse ACSURL: %w", err)
	}
	metadataURL, err := url.Parse(cfg.EntityID)
	if err != nil {
		// EntityID isn't required to be a URL by SAML, but most
		// deployments do use the metadata URL. If it isn't a URL,
		// fall back to a synthesized one matching ACS (SP metadata
		// is hosted alongside ACS in our routing).
		metadataURL = &url.URL{}
	}

	var idpMetadata *crewjam.EntityDescriptor
	if cfg.IDPMetadataXML != "" {
		idpMetadata, err = parseMetadataXML([]byte(cfg.IDPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("saml: parse IDPMetadataXML: %w", err)
		}
	} else {
		idpMetadata, err = fetchIDPMetadata(ctx, cfg.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("saml: fetch IDPMetadataURL %s: %w", cfg.IDPMetadataURL, err)
		}
	}

	sp := &crewjam.ServiceProvider{
		EntityID:    cfg.EntityID,
		AcsURL:      *acsURL,
		MetadataURL: *metadataURL,
		IDPMetadata: idpMetadata,
		// We deliberately do NOT set SignatureMethod — that would
		// enable AuthnRequest signing, which we've explicitly
		// deferred to v2 (decision D5 in the spec). Most IdPs
		// accept unsigned AuthnRequests when the SP is registered
		// with a known EntityID + ACS URL.
		AuthnNameIDFormat: crewjam.UnspecifiedNameIDFormat,
	}

	return &Provider{
		cfg:         cfg,
		sp:          sp,
		replayCache: newReplayCache(time.Duration(cfg.effectiveReplayWindow()) * time.Minute),
	}, nil
}

// Type identifies this provider as SAML.
func (p *Provider) Type() string { return auth.TypeSAML }

// Metadata returns the SP metadata XML bytes that should be served
// at the SP metadata endpoint. The IdP fetches this to learn the SP's
// EntityID and ACS URL.
func (p *Provider) Metadata() ([]byte, error) {
	md := p.sp.Metadata()
	buf, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("saml: marshal metadata: %w", err)
	}
	return buf, nil
}

// LoginURL builds the IdP SSO URL the user's browser should be
// redirected to. state.OAuthState travels as RelayState — the IdP
// echoes it back on the ACS POST verbatim, and HandleCallback
// validates the echo against the state cookie. This is the SAML
// equivalent of the OAuth2 state parameter.
//
// SAML has no protocol slot equivalent to the OIDC nonce, so
// state.Nonce is unused here. We still REQUIRE it to be present so
// the State invariant (Nonce and OAuthState are independent random
// values) holds uniformly across providers — a caller that fills
// only OAuthState would mask a subtle bug if the deployment later
// added a second provider.
//
// state.Verifier is unused for SAML (no PKCE equivalent in the SAML
// Web Browser SSO profile); we accept it for interface uniformity
// but ignore it.
func (p *Provider) LoginURL(_ context.Context, state auth.State) (string, error) {
	if state.EnvUUID == "" {
		return "", fmt.Errorf("saml: LoginURL: empty State.EnvUUID")
	}
	if state.OAuthState == "" {
		return "", fmt.Errorf("saml: LoginURL: empty State.OAuthState")
	}
	u, err := p.sp.MakeRedirectAuthenticationRequest(state.OAuthState)
	if err != nil {
		return "", fmt.Errorf("saml: MakeRedirectAuthenticationRequest: %w", err)
	}
	return u.String(), nil
}

// HandleCallback consumes the SAML ACS POST and returns a
// ResolvedIdentity. Validates, in order:
//
//  1. POST has a SAMLResponse form field (ErrMissingSAMLResponse)
//  2. RelayState echoes state.Nonce (ErrStateMismatch — S10)
//  3. crewjam ParseResponse validates: signature, issuer, audience,
//     NotBefore/NotOnOrAfter, recipient, InResponseTo, signed
//     assertion enforcement (ErrParseResponse — S1, S2, S4, S5, S6, S7)
//  4. Assertion ID has not been seen recently (ErrReplay — S3)
//  5. Required-groups gate, if configured (ErrGroupNotAllowed)
//  6. Resolved username passes sanitizeUsername (ErrUsernameInvalid)
//
// Implementations MUST NOT trust the caller to pre-verify any of the
// above. This is the security perimeter.
func (p *Provider) HandleCallback(_ context.Context, r *http.Request, state auth.State) (auth.ResolvedIdentity, error) {
	if err := r.ParseForm(); err != nil {
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: parse form: %v", ErrParseResponse, err)
	}

	// (1) SAMLResponse field must be present.
	if r.PostForm.Get("SAMLResponse") == "" {
		return auth.ResolvedIdentity{}, ErrMissingSAMLResponse
	}

	// (2) RelayState must echo state.OAuthState. Load-bearing CSRF
	// defense — an attacker without our state cookie cannot mint a
	// RelayState that survives this check.
	if got := r.PostForm.Get("RelayState"); got != state.OAuthState {
		return auth.ResolvedIdentity{}, ErrStateMismatch
	}

	// (3) crewjam handles XML parsing, signature verification, all
	// timestamp checks, audience restriction, recipient match, and
	// InResponseTo. We pass no possibleRequestIDs because we don't
	// (yet) track outstanding AuthnRequest IDs — InResponseTo
	// validation is "if present, must match one of the IDs we have."
	// Empty list means crewjam accepts unsolicited responses, which
	// is the SP-initiated-only profile we documented. The state-cookie
	// CSRF check above still binds the response to a specific browser.
	assertion, err := p.sp.ParseResponse(r, nil)
	if err != nil {
		// crewjam returns a wrapped error with detailed reasons.
		// Log the detail server-side but return only the sentinel.
		log.Warn().Err(err).Msg("saml: ParseResponse failed")
		return auth.ResolvedIdentity{}, fmt.Errorf("%w: %v", ErrParseResponse, err)
	}

	// (4) Replay defense — the assertion just passed signature +
	// timestamp checks, but an attacker who captured a single valid
	// assertion could replay it. Reject duplicates within the configured
	// window. The replay cache is keyed by assertion.ID, which the SAML
	// spec requires to be unique per assertion.
	if assertion.ID != "" && !p.replayCache.remember(assertion.ID) {
		return auth.ResolvedIdentity{}, ErrReplay
	}

	// Extract NameID and attributes for downstream use. The Subject is
	// always present after a successful ParseResponse (crewjam requires
	// it), but defensively check.
	var nameIDValue, nameIDFormat string
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameIDValue = assertion.Subject.NameID.Value
		nameIDFormat = assertion.Subject.NameID.Format
	}

	attrs := collectAttributes(assertion)

	// (5) Required-groups gate.
	if len(p.cfg.RequiredGroups) > 0 {
		if !hasSAMLRequiredGroup(attrs, p.cfg.GroupsAttribute, p.cfg.RequiredGroups) {
			return auth.ResolvedIdentity{}, ErrGroupNotAllowed
		}
	}

	// Resolve preferred username.
	username := pickSAMLUsername(nameIDValue, attrs, p.cfg.UsernameAttribute)
	if username == "" {
		return auth.ResolvedIdentity{}, ErrUsernameInvalid
	}

	// (6) Character-class validation. Same regex as OIDC.
	var clean string
	if p.cfg.LegacyPermissiveUsername {
		clean = strings.TrimSpace(username)
		if clean == "" {
			return auth.ResolvedIdentity{}, ErrUsernameInvalid
		}
	} else {
		clean = sanitizeUsername(username)
		if clean == "" {
			return auth.ResolvedIdentity{}, ErrUsernameInvalid
		}
	}

	// Compose display name from the standard SAML "name" attribute or
	// givenName + sn if present. Best-effort; empty when the IdP didn't
	// emit either.
	displayName := firstAttribute(attrs, "displayName", "name", samlAttrCommonName)
	if displayName == "" {
		given := firstAttribute(attrs, samlAttrGivenName, "givenName")
		sn := firstAttribute(attrs, samlAttrSurname, "sn", "surname")
		displayName = strings.TrimSpace(given + " " + sn)
	}

	email := firstAttribute(attrs, samlAttrEmailAddress, "email", "mail")
	groups := decodeSAMLGroups(attrs, p.cfg.GroupsAttribute)

	// rawClaims surfaces the attribute soup as a generic map for
	// debugging and future extension points. Callers MUST NOT bypass
	// the typed fields by reading raw — same contract as OIDC.Raw.
	rawClaims := make(map[string]any, len(attrs)+2)
	for name, values := range attrs {
		// Single-valued attributes are flattened to a string;
		// multi-valued ones stay as []string. Matches the shape
		// JS consumers expect on the OIDC side.
		if len(values) == 1 {
			rawClaims[name] = values[0]
		} else {
			rawClaims[name] = values
		}
	}
	if nameIDValue != "" {
		rawClaims["__nameid"] = nameIDValue
	}
	if nameIDFormat != "" {
		rawClaims["__nameid_format"] = nameIDFormat
	}

	return auth.ResolvedIdentity{
		Subject:           nameIDValue, // SAML's stable identity field
		PreferredUsername: clean,
		Email:             email,
		Name:              displayName,
		Groups:            groups,
		Raw:               rawClaims,
		// IDToken is unset — SAML doesn't have one. RP-initiated
		// logout (SLO) is deferred to v2 (decision D3).
	}, nil
}

// parseMetadataXML deserializes the operator-provided metadata XML.
// Reads only — no network access.
func parseMetadataXML(b []byte) (*crewjam.EntityDescriptor, error) {
	var ed crewjam.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil {
		// crewjam metadata is wrapped in EntitiesDescriptor in some
		// real-world deployments. Try once more.
		var eds crewjam.EntitiesDescriptor
		if err2 := xml.Unmarshal(b, &eds); err2 == nil && len(eds.EntityDescriptors) > 0 {
			return &eds.EntityDescriptors[0], nil
		}
		return nil, err
	}
	return &ed, nil
}

// fetchIDPMetadata pulls and parses the IdP metadata document. Bounded
// by httpMetadataTimeout independent of the caller context.
func fetchIDPMetadata(parentCtx context.Context, metadataURL string) (*crewjam.EntityDescriptor, error) {
	ctx, cancel := context.WithTimeout(parentCtx, httpMetadataTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			// Operators must use https in production; we still
			// allow http for dev Keycloak. Skip-verify is NEVER
			// enabled here.
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		Timeout: httpMetadataTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, err
	}
	return parseMetadataXML(body)
}
