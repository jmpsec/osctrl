package mfa

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn wraps go-webauthn with the storage in this package. It covers both
// roaming security keys (YubiKey and friends) and passkeys — from the relying
// party's side they are the same ceremony, they differ only in where the
// private key lives.
type WebAuthn struct {
	wa  *webauthn.WebAuthn
	mgr *Manager
}

// NewWebAuthn builds the relying party. rpID is the registrable domain the
// credentials are scoped to ("osctrl.example.com"), and origins are the exact
// origins the SPA is served from ("https://osctrl.example.com"). Both must
// match what the browser sees or every ceremony fails at the browser, before
// it ever reaches us.
func NewWebAuthn(mgr *Manager, rpID, displayName string, origins []string) (*WebAuthn, error) {
	if rpID == "" {
		return nil, fmt.Errorf("mfa: WebAuthn requires an RP ID")
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("mfa: WebAuthn requires at least one origin")
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: configuring WebAuthn: %w", err)
	}
	return &WebAuthn{wa: wa, mgr: mgr}, nil
}

// waUser adapts an osctrl username plus its stored credentials to the
// webauthn.User interface.
type waUser struct {
	username string
	creds    []webauthn.Credential
}

// WebAuthnID is the user handle the authenticator stores alongside the
// credential. The spec recommends 64 random bytes; we derive it from the
// username instead so it is stable without another table to keep in sync.
// It is domain-separated and hashed so the raw username is not written to
// the authenticator, and it never carries authorization meaning on its own —
// every ceremony here starts from a username we already resolved.
func (u waUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte("osctrl-webauthn-user:" + u.username))
	return sum[:]
}

func (u waUser) WebAuthnName() string                       { return u.username }
func (u waUser) WebAuthnDisplayName() string                { return u.username }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// user loads a user with their stored credentials.
func (w *WebAuthn) user(username string) (waUser, error) {
	stored, err := w.mgr.Credentials(username)
	if err != nil {
		return waUser{}, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		converted, err := toWebAuthnCredential(c)
		if err != nil {
			// One unreadable row must not lock the user out of the
			// authenticators that still work.
			continue
		}
		creds = append(creds, converted)
	}
	return waUser{username: username, creds: creds}, nil
}

// BeginRegistration returns the creation options the browser passes to
// navigator.credentials.create(), plus the session blob to hand back on
// finish. Registration is scoped to a challenge row so the ceremony state is
// server-side and single-use.
func (w *WebAuthn) BeginRegistration(username string) (*protocol.CredentialCreation, string, error) {
	user, err := w.user(username)
	if err != nil {
		return nil, "", err
	}
	// Exclude what is already registered so a user cannot silently
	// re-register the same authenticator twice.
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.creds))
	for _, c := range user.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := w.wa.BeginRegistration(user,
		webauthn.WithExclusions(exclude),
		// Second factor, not passwordless: the password step already
		// identified the user, so a resident key is not required and
		// user verification stays the authenticator's choice (a PIN-less
		// security key tap is a valid second factor).
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("mfa: beginning registration: %w", err)
	}
	blob, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("mfa: encoding session: %w", err)
	}
	return creation, string(blob), nil
}

// FinishRegistration validates the attestation and returns the credential row
// to store. `name` is the operator-supplied label.
func (w *WebAuthn) FinishRegistration(username, name, sessionBlob string, response json.RawMessage) (*Credential, error) {
	user, err := w.user(username)
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionBlob), &session); err != nil {
		return nil, ErrChallenge
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("mfa: parsing attestation: %w", err)
	}
	cred, err := w.wa.CreateCredential(user, session, parsed)
	if err != nil {
		return nil, fmt.Errorf("mfa: validating attestation: %w", err)
	}
	return fromWebAuthnCredential(username, name, cred), nil
}

// BeginLogin returns the assertion options for navigator.credentials.get()
// and the session blob for the finish step.
func (w *WebAuthn) BeginLogin(username string) (*protocol.CredentialAssertion, string, error) {
	user, err := w.user(username)
	if err != nil {
		return nil, "", err
	}
	if len(user.creds) == 0 {
		return nil, "", ErrNotEnrolled
	}
	assertion, session, err := w.wa.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("mfa: beginning login: %w", err)
	}
	blob, err := json.Marshal(session)
	if err != nil {
		return nil, "", fmt.Errorf("mfa: encoding session: %w", err)
	}
	return assertion, string(blob), nil
}

// FinishLogin validates an assertion and records the new signature counter.
func (w *WebAuthn) FinishLogin(username, sessionBlob string, response json.RawMessage) error {
	user, err := w.user(username)
	if err != nil {
		return err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionBlob), &session); err != nil {
		return ErrChallenge
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return ErrInvalidCode
	}
	cred, err := w.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		return ErrInvalidCode
	}
	return w.mgr.TouchCredential(username, encodeCredentialID(cred.ID), cred.Authenticator.SignCount, cred.Authenticator.CloneWarning)
}

// encodeCredentialID is the string form used in the DB and the API. base64url
// without padding is what the WebAuthn JSON serialization uses, so the SPA can
// pass the value straight back.
func encodeCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

func toWebAuthnCredential(c Credential) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
	if err != nil {
		return webauthn.Credential{}, fmt.Errorf("mfa: decoding credential id: %w", err)
	}
	transports := make([]protocol.AuthenticatorTransport, 0)
	for _, t := range strings.Split(c.Transports, ",") {
		if t != "" {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:              id,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.AAGUID,
			SignCount:    c.SignCount,
			CloneWarning: c.CloneWarning,
		},
	}, nil
}

func fromWebAuthnCredential(username, name string, c *webauthn.Credential) *Credential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return &Credential{
		Username:        username,
		Name:            name,
		CredentialID:    encodeCredentialID(c.ID),
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		AAGUID:          c.Authenticator.AAGUID,
		SignCount:       c.Authenticator.SignCount,
		CloneWarning:    c.Authenticator.CloneWarning,
		Transports:      strings.Join(transports, ","),
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
	}
}
