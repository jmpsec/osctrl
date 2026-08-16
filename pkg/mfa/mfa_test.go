package mfa

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err, "Failed to open in-memory database")
	require.NoError(t, db.AutoMigrate(&TOTPEnrollment{}, &RecoveryCode{}, &Credential{}, &Challenge{}))
	return &Manager{DB: db}
}

// RFC 6238 Appendix B publishes expected values for the ASCII secret
// "12345678901234567890" with SHA1. Anything that breaks the HMAC, the
// counter encoding or the dynamic truncation shows up here.
func TestCodeMatchesRFC6238Vectors(t *testing.T) {
	secret := base32NoPad.EncodeToString([]byte("12345678901234567890"))
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		code, err := Code(secret, Step(time.Unix(c.unix, 0)))
		require.NoError(t, err)
		assert.Equal(t, c.want, code, "code at unix %d", c.unix)
	}
}

func TestValidateAcceptsDriftAndRejectsReplay(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	now := time.Now()

	current, err := Code(secret, Step(now))
	require.NoError(t, err)
	step, ok := Validate(secret, current, now, 0)
	require.True(t, ok, "current code should validate")

	// One step of clock drift either way is tolerated.
	previous, err := Code(secret, Step(now)-1)
	require.NoError(t, err)
	_, ok = Validate(secret, previous, now, 0)
	assert.True(t, ok, "one step of drift should validate")

	// Two steps out is refused.
	stale, err := Code(secret, Step(now)-2)
	require.NoError(t, err)
	_, ok = Validate(secret, stale, now, 0)
	assert.False(t, ok, "two steps of drift should be refused")

	// The same code cannot be used twice: its step is now burned.
	_, ok = Validate(secret, current, now, step)
	assert.False(t, ok, "replayed code should be refused")

	assert.False(t, func() bool { _, ok := Validate(secret, "000", now, 0); return ok }(), "short code refused")
	assert.False(t, func() bool { _, ok := Validate(secret, "123456", now, 0); return ok }(), "wrong code refused")
}

func TestGenerateSecretIsDecodableBase32(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	assert.Len(t, raw, secretBytes)
}

func TestProvisioningURICarriesIssuerAndSecret(t *testing.T) {
	uri := ProvisioningURI("osctrl", "admin", "ABCDEF")
	assert.Contains(t, uri, "otpauth://totp/osctrl:admin?")
	assert.Contains(t, uri, "secret=ABCDEF")
	assert.Contains(t, uri, "issuer=osctrl")
	assert.Contains(t, uri, "digits=6")
	assert.Contains(t, uri, "period=30")
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	m := setupTestManager(t)
	codes, err := m.RegenerateRecoveryCodes("admin")
	require.NoError(t, err)
	require.Len(t, codes, RecoveryCodeCount)

	// Formatting is cosmetic: lowercase and dashes both resolve.
	require.NoError(t, m.VerifyRecoveryCode("admin", codes[0]))
	assert.ErrorIs(t, m.VerifyRecoveryCode("admin", codes[0]), ErrInvalidCode, "second use must fail")

	st, err := m.Status("admin")
	require.NoError(t, err)
	assert.Equal(t, RecoveryCodeCount-1, st.RecoveryCodesLeft)

	assert.ErrorIs(t, m.VerifyRecoveryCode("admin", "NOT-A-REAL-CODE"), ErrInvalidCode)
	assert.ErrorIs(t, m.VerifyRecoveryCode("other", codes[1]), ErrInvalidCode, "codes are per user")
}

func TestRegenerateReplacesPreviousCodes(t *testing.T) {
	m := setupTestManager(t)
	first, err := m.RegenerateRecoveryCodes("admin")
	require.NoError(t, err)
	second, err := m.RegenerateRecoveryCodes("admin")
	require.NoError(t, err)

	assert.ErrorIs(t, m.VerifyRecoveryCode("admin", first[0]), ErrInvalidCode, "old codes must stop working")
	assert.NoError(t, m.VerifyRecoveryCode("admin", second[0]))
}

func TestTOTPEnrollmentLifecycle(t *testing.T) {
	m := setupTestManager(t)
	assert.False(t, m.Enabled("admin"), "no factors means MFA is not enabled")

	secret, err := m.BeginTOTP("admin")
	require.NoError(t, err)
	assert.False(t, m.Enabled("admin"), "unconfirmed enrollment must not gate login")

	// A wrong code leaves the enrollment pending.
	_, err = m.ConfirmTOTP("admin", "000000")
	assert.ErrorIs(t, err, ErrInvalidCode)
	assert.False(t, m.Enabled("admin"))

	code, err := Code(secret, Step(time.Now()))
	require.NoError(t, err)
	codes, err := m.ConfirmTOTP("admin", code)
	require.NoError(t, err)
	assert.Len(t, codes, RecoveryCodeCount, "confirming hands out recovery codes")
	assert.True(t, m.Enabled("admin"))

	// The confirmation code is burned, so it cannot log in again.
	assert.ErrorIs(t, m.VerifyTOTP("admin", code), ErrInvalidCode)

	next, err := Code(secret, Step(time.Now())+1)
	require.NoError(t, err)
	assert.NoError(t, m.VerifyTOTP("admin", next))

	require.NoError(t, m.DisableTOTP("admin"))
	assert.False(t, m.Enabled("admin"))
	st, err := m.Status("admin")
	require.NoError(t, err)
	assert.Zero(t, st.RecoveryCodesLeft, "recovery codes go with the last factor")
	assert.ErrorIs(t, m.VerifyTOTP("admin", next), ErrNotEnrolled)
}

// Removing a factor must leave the account able to enroll again — a
// soft-deleted row would otherwise keep the username taken.
func TestTOTPCanBeReEnrolledAfterRemoval(t *testing.T) {
	m := setupTestManager(t)
	secret, err := m.BeginTOTP("admin")
	require.NoError(t, err)
	code, err := Code(secret, Step(time.Now()))
	require.NoError(t, err)
	_, err = m.ConfirmTOTP("admin", code)
	require.NoError(t, err)
	require.NoError(t, m.DisableTOTP("admin"))

	second, err := m.BeginTOTP("admin")
	require.NoError(t, err, "re-enrolling after removal must work")
	assert.NotEqual(t, secret, second, "re-enrollment issues a fresh secret")
	next, err := Code(second, Step(time.Now())+1)
	require.NoError(t, err)
	_, err = m.ConfirmTOTP("admin", next)
	require.NoError(t, err)
	assert.True(t, m.Enabled("admin"))
}

// A credential deleted and registered again keeps working: same index concern.
func TestCredentialCanBeRegisteredAgainAfterRemoval(t *testing.T) {
	m := setupTestManager(t)
	require.NoError(t, m.AddCredential(&Credential{Username: "admin", CredentialID: "aWQ", PublicKey: []byte("pk")}))
	require.NoError(t, m.DeleteCredential("admin", "aWQ"))
	require.NoError(t, m.AddCredential(&Credential{Username: "admin", CredentialID: "aWQ", PublicKey: []byte("pk")}))
	assert.True(t, m.Enabled("admin"))
}

func TestBeginTOTPRefusesWhenAlreadyEnabled(t *testing.T) {
	m := setupTestManager(t)
	secret, err := m.BeginTOTP("admin")
	require.NoError(t, err)
	code, err := Code(secret, Step(time.Now()))
	require.NoError(t, err)
	_, err = m.ConfirmTOTP("admin", code)
	require.NoError(t, err)

	_, err = m.BeginTOTP("admin")
	assert.Error(t, err, "re-enrolling would silently replace a working factor")
}

func TestChallengesAreSingleUseAndExpire(t *testing.T) {
	m := setupTestManager(t)
	id, err := m.NewChallenge("admin", PurposeLogin, 3)
	require.NoError(t, err)

	challenge, err := m.GetChallenge(id, PurposeLogin)
	require.NoError(t, err)
	assert.Equal(t, "admin", challenge.Username)
	assert.Equal(t, 3, challenge.ExpHours)

	_, err = m.GetChallenge(id, PurposeRegister)
	assert.ErrorIs(t, err, ErrChallenge, "purpose is part of the lookup")

	require.NoError(t, m.ConsumeChallenge(id))
	assert.ErrorIs(t, m.ConsumeChallenge(id), ErrChallenge, "a challenge mints one session only")
	_, err = m.GetChallenge(id, PurposeLogin)
	assert.ErrorIs(t, err, ErrChallenge)

	expired, err := m.NewChallenge("admin", PurposeLogin, 0)
	require.NoError(t, err)
	require.NoError(t, m.DB.Model(&Challenge{}).Where("challenge_id = ?", expired).
		Update("expires_at", time.Now().Add(-time.Minute)).Error)
	_, err = m.GetChallenge(expired, PurposeLogin)
	assert.ErrorIs(t, err, ErrChallenge)
}

func TestCredentialsGateMFAAndCleanUp(t *testing.T) {
	m := setupTestManager(t)
	require.NoError(t, m.AddCredential(&Credential{
		Username:     "admin",
		Name:         "YubiKey",
		CredentialID: "Y3JlZC1pZA",
		PublicKey:    []byte("pk"),
	}))
	assert.True(t, m.Enabled("admin"), "a security key alone enables MFA")

	_, err := m.RegenerateRecoveryCodes("admin")
	require.NoError(t, err)

	require.NoError(t, m.DeleteCredential("admin", "Y3JlZC1pZA"))
	assert.False(t, m.Enabled("admin"))
	st, err := m.Status("admin")
	require.NoError(t, err)
	assert.Zero(t, st.RecoveryCodesLeft)

	assert.Error(t, m.DeleteCredential("admin", "Y3JlZC1pZA"), "deleting twice is an error")
}

func TestDeleteUserRemovesEveryFactor(t *testing.T) {
	m := setupTestManager(t)
	secret, err := m.BeginTOTP("admin")
	require.NoError(t, err)
	code, err := Code(secret, Step(time.Now()))
	require.NoError(t, err)
	_, err = m.ConfirmTOTP("admin", code)
	require.NoError(t, err)
	require.NoError(t, m.AddCredential(&Credential{Username: "admin", CredentialID: "aWQ", PublicKey: []byte("pk")}))

	require.NoError(t, m.DeleteUser("admin"))
	st, err := m.Status("admin")
	require.NoError(t, err)
	assert.False(t, st.TOTPEnabled)
	assert.Empty(t, st.Credentials)
	assert.Zero(t, st.RecoveryCodesLeft)
}
