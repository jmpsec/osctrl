// Package mfa implements the second authentication factor for password
// (`db`) logins: TOTP authenticator apps, WebAuthn credentials (passkeys and
// hardware security keys) and single-use recovery codes.
//
// Federated logins (SAML/OIDC) are out of scope — the identity provider owns
// the factor policy there. Service users are out of scope too: they
// authenticate with a long-lived token, not an interactive login.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// TOTP parameters. RFC 6238 leaves these open, but SHA1 / 6 digits / 30s is
// what every authenticator app (Google Authenticator, Authy, 1Password,
// Aegis…) actually implements, and what an otpauth:// URI defaults to.
const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkew is how many steps either side of the current one are
	// accepted, to tolerate clock drift between the phone and the server.
	// One step = ±30s, the usual compromise; wider windows linearly widen
	// the replay window for a shoulder-surfed code.
	totpSkew = 1
	// secretBytes is the shared-secret size. RFC 4226 requires at least
	// 128 bits and recommends 160 — which is also the SHA1 block output,
	// so nothing is wasted.
	secretBytes = 20
)

// base32NoPad is the encoding authenticator apps expect in otpauth:// URIs:
// standard RFC 4648 base32, uppercase, no "=" padding.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new base32-encoded TOTP shared secret.
func GenerateSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mfa: reading random secret: %w", err)
	}
	return base32NoPad.EncodeToString(buf), nil
}

// ProvisioningURI builds the otpauth:// URI that is encoded into the QR code
// during enrollment. `issuer` labels the deployment in the authenticator app
// and `account` identifies the user within it.
func ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step returns the RFC 6238 time step a given instant falls into. Steps are
// persisted per user so a code cannot be replayed inside its validity window.
func Step(t time.Time) int64 {
	return t.UTC().Unix() / int64(totpPeriod.Seconds())
}

// Code computes the TOTP value for a secret at a given time step.
func Code(secret string, step int64) (string, error) {
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("mfa: decoding secret: %w", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	// Dynamic truncation, RFC 4226 §5.4.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range totpDigits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// Validate checks a user-supplied code against the secret around `now`,
// accepting ±totpSkew steps of drift. `lastStep` is the most recent step this
// user already authenticated with; steps at or below it are refused so a code
// observed over someone's shoulder cannot be used a second time while it is
// still in its window.
//
// It returns the step the code matched, which the caller MUST persist as the
// new lastStep for the user.
func Validate(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	current := Step(now)
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step <= lastStep {
			continue
		}
		want, err := Code(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// QRDataURI renders a provisioning URI as a PNG data URI, so the SPA can show
// the enrollment QR code with a plain <img> and no client-side QR library.
func QRDataURI(uri string) (string, error) {
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return "", fmt.Errorf("mfa: encoding QR code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
