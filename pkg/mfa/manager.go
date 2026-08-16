package mfa

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// Errors callers match on to pick an HTTP status. They are deliberately
// coarse: the login path must not tell an attacker whether the username, the
// challenge or the code was the part that did not check out.
var (
	// ErrNotEnrolled means the user has no usable second factor.
	ErrNotEnrolled = errors.New("mfa: user is not enrolled")
	// ErrInvalidCode covers a wrong, expired or already-used code.
	ErrInvalidCode = errors.New("mfa: invalid code")
	// ErrChallenge covers an unknown, expired or already-consumed challenge.
	ErrChallenge = errors.New("mfa: invalid challenge")
)

// Manager owns the MFA tables.
type Manager struct {
	DB *gorm.DB
}

// NewManager initializes the manager and migrates the MFA tables.
func NewManager(backend *gorm.DB) *Manager {
	m := &Manager{DB: backend}
	if err := backend.AutoMigrate(&TOTPEnrollment{}, &RecoveryCode{}, &Credential{}, &Challenge{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate MFA tables: %v", err)
	}
	return m
}

// Status is what the profile page and the login flow need to know about a
// user's factors. It never carries the TOTP secret.
type Status struct {
	TOTPEnabled       bool         `json:"totp_enabled"`
	Credentials       []Credential `json:"credentials"`
	RecoveryCodesLeft int          `json:"recovery_codes_left"`
}

// Status returns the enrolled factors for a user.
func (m *Manager) Status(username string) (Status, error) {
	var st Status
	var totp TOTPEnrollment
	err := m.DB.Where("username = ? AND confirmed = ?", username, true).First(&totp).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return st, fmt.Errorf("mfa: reading TOTP enrollment: %w", err)
	}
	st.TOTPEnabled = err == nil
	creds, err := m.Credentials(username)
	if err != nil {
		return st, err
	}
	st.Credentials = creds
	var left int64
	if err := m.DB.Model(&RecoveryCode{}).Where("username = ? AND used_at IS NULL", username).Count(&left).Error; err != nil {
		return st, fmt.Errorf("mfa: counting recovery codes: %w", err)
	}
	st.RecoveryCodesLeft = int(left)
	return st, nil
}

// Enabled reports whether the user must present a second factor to log in.
func (m *Manager) Enabled(username string) bool {
	st, err := m.Status(username)
	if err != nil {
		// Fail closed: if we cannot tell, ask for the second factor. A
		// user with no factors then cannot satisfy it and login fails,
		// which is the safe direction for an auth check.
		log.Err(err).Str("user", username).Msg("mfa: status lookup failed")
		return true
	}
	return st.TOTPEnabled || len(st.Credentials) > 0
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// BeginTOTP starts (or restarts) an enrollment and returns the shared secret.
// The row stays unconfirmed until ConfirmTOTP succeeds, so calling this on an
// account that already has TOTP does not disable the working factor: the
// existing confirmed row is kept until the new one is confirmed.
func (m *Manager) BeginTOTP(username string) (string, error) {
	if m.hasConfirmedTOTP(username) {
		return "", fmt.Errorf("mfa: TOTP already enabled for %s", username)
	}
	secret, err := GenerateSecret()
	if err != nil {
		return "", err
	}
	enrollment := TOTPEnrollment{Username: username, Secret: secret, Confirmed: false, LastStep: 0}
	// One row per user: replace whatever half-finished enrollment was there.
	// Unscoped, because a soft-deleted row keeps its place in the unique
	// index on username and would collide with the row created below.
	if err := m.DB.Unscoped().Where("username = ?", username).Delete(&TOTPEnrollment{}).Error; err != nil {
		return "", fmt.Errorf("mfa: clearing previous enrollment: %w", err)
	}
	if err := m.DB.Create(&enrollment).Error; err != nil {
		return "", fmt.Errorf("mfa: creating enrollment: %w", err)
	}
	return secret, nil
}

// ConfirmTOTP completes an enrollment by checking a code generated from the
// pending secret, and returns a fresh set of recovery codes.
func (m *Manager) ConfirmTOTP(username, code string) ([]string, error) {
	var enrollment TOTPEnrollment
	if err := m.DB.Where("username = ?", username).First(&enrollment).Error; err != nil {
		return nil, ErrNotEnrolled
	}
	if enrollment.Confirmed {
		return nil, fmt.Errorf("mfa: TOTP already enabled for %s", username)
	}
	step, ok := Validate(enrollment.Secret, code, time.Now(), enrollment.LastStep)
	if !ok {
		return nil, ErrInvalidCode
	}
	if err := m.DB.Model(&enrollment).Updates(map[string]any{"confirmed": true, "last_step": step}).Error; err != nil {
		return nil, fmt.Errorf("mfa: confirming enrollment: %w", err)
	}
	return m.RegenerateRecoveryCodes(username)
}

// CompleteEnrollment confirms a TOTP secret that was carried on a challenge
// rather than stored against the user — the forced-enrollment-at-login path,
// where nothing should be written until the user proves the secret works.
func (m *Manager) CompleteEnrollment(username, secret, code string) ([]string, error) {
	step, ok := Validate(secret, code, time.Now(), 0)
	if !ok {
		return nil, ErrInvalidCode
	}
	if err := m.DB.Unscoped().Where("username = ?", username).Delete(&TOTPEnrollment{}).Error; err != nil {
		return nil, fmt.Errorf("mfa: clearing previous enrollment: %w", err)
	}
	enrollment := TOTPEnrollment{Username: username, Secret: secret, Confirmed: true, LastStep: step}
	if err := m.DB.Create(&enrollment).Error; err != nil {
		return nil, fmt.Errorf("mfa: creating enrollment: %w", err)
	}
	return m.RegenerateRecoveryCodes(username)
}

// VerifyTOTP checks a login-time code and burns its time step.
func (m *Manager) VerifyTOTP(username, code string) error {
	var enrollment TOTPEnrollment
	if err := m.DB.Where("username = ? AND confirmed = ?", username, true).First(&enrollment).Error; err != nil {
		return ErrNotEnrolled
	}
	step, ok := Validate(enrollment.Secret, code, time.Now(), enrollment.LastStep)
	if !ok {
		return ErrInvalidCode
	}
	if err := m.DB.Model(&enrollment).Update("last_step", step).Error; err != nil {
		return fmt.Errorf("mfa: recording used step: %w", err)
	}
	return nil
}

// DisableTOTP removes the authenticator factor. Recovery codes are dropped
// with it when no WebAuthn credential is left, since they would otherwise be
// a standalone bypass of a factor the user believes they turned off.
func (m *Manager) DisableTOTP(username string) error {
	// Unscoped so the username is free for a later re-enrollment: the
	// unique index does not ignore soft-deleted rows.
	if err := m.DB.Unscoped().Where("username = ?", username).Delete(&TOTPEnrollment{}).Error; err != nil {
		return fmt.Errorf("mfa: deleting enrollment: %w", err)
	}
	return m.dropOrphanRecoveryCodes(username)
}

func (m *Manager) hasConfirmedTOTP(username string) bool {
	var count int64
	if err := m.DB.Model(&TOTPEnrollment{}).Where("username = ? AND confirmed = ?", username, true).Count(&count).Error; err != nil {
		return false
	}
	return count > 0
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// RegenerateRecoveryCodes replaces every code for the user and returns the new
// plaintext set — the only time it is ever available.
func (m *Manager) RegenerateRecoveryCodes(username string) ([]string, error) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		return nil, err
	}
	err = m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("username = ?", username).Delete(&RecoveryCode{}).Error; err != nil {
			return err
		}
		rows := make([]RecoveryCode, 0, len(codes))
		for _, c := range codes {
			rows = append(rows, RecoveryCode{Username: username, CodeHash: HashRecoveryCode(c)})
		}
		return tx.Create(&rows).Error
	})
	if err != nil {
		return nil, fmt.Errorf("mfa: storing recovery codes: %w", err)
	}
	return codes, nil
}

// VerifyRecoveryCode consumes one unused recovery code.
func (m *Manager) VerifyRecoveryCode(username, code string) error {
	var rows []RecoveryCode
	if err := m.DB.Where("username = ? AND used_at IS NULL", username).Find(&rows).Error; err != nil {
		return fmt.Errorf("mfa: reading recovery codes: %w", err)
	}
	for _, row := range rows {
		if !MatchRecoveryCode(code, row.CodeHash) {
			continue
		}
		now := time.Now()
		// Only claim the row if it is still unused, so two concurrent
		// requests carrying the same code cannot both succeed.
		res := m.DB.Model(&RecoveryCode{}).
			Where("id = ? AND used_at IS NULL", row.ID).
			Update("used_at", &now)
		if res.Error != nil {
			return fmt.Errorf("mfa: consuming recovery code: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return ErrInvalidCode
		}
		return nil
	}
	return ErrInvalidCode
}

// dropOrphanRecoveryCodes deletes recovery codes once the user has no factor
// left for them to back up.
func (m *Manager) dropOrphanRecoveryCodes(username string) error {
	st, err := m.Status(username)
	if err != nil {
		return err
	}
	if st.TOTPEnabled || len(st.Credentials) > 0 {
		return nil
	}
	if err := m.DB.Unscoped().Where("username = ?", username).Delete(&RecoveryCode{}).Error; err != nil {
		return fmt.Errorf("mfa: deleting recovery codes: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// WebAuthn credentials
// ---------------------------------------------------------------------------

// Credentials lists the WebAuthn authenticators registered by a user.
func (m *Manager) Credentials(username string) ([]Credential, error) {
	var creds []Credential
	if err := m.DB.Where("username = ?", username).Order("created_at asc").Find(&creds).Error; err != nil {
		return nil, fmt.Errorf("mfa: reading credentials: %w", err)
	}
	return creds, nil
}

// AddCredential stores a freshly registered authenticator.
func (m *Manager) AddCredential(cred *Credential) error {
	if err := m.DB.Create(cred).Error; err != nil {
		return fmt.Errorf("mfa: storing credential: %w", err)
	}
	return nil
}

// DeleteCredential removes one authenticator belonging to the user.
func (m *Manager) DeleteCredential(username, credentialID string) error {
	res := m.DB.Unscoped().Where("username = ? AND credential_id = ?", username, credentialID).Delete(&Credential{})
	if res.Error != nil {
		return fmt.Errorf("mfa: deleting credential: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return m.dropOrphanRecoveryCodes(username)
}

// TouchCredential records a successful assertion.
func (m *Manager) TouchCredential(username, credentialID string, signCount uint32, cloneWarning bool) error {
	now := time.Now()
	err := m.DB.Model(&Credential{}).
		Where("username = ? AND credential_id = ?", username, credentialID).
		Updates(map[string]any{"sign_count": signCount, "clone_warning": cloneWarning, "last_used_at": &now}).Error
	if err != nil {
		return fmt.Errorf("mfa: updating credential: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

// NewChallenge stores a challenge and returns its opaque id.
func (m *Manager) NewChallenge(username, purpose string, expHours int) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mfa: generating challenge id: %w", err)
	}
	id := hex.EncodeToString(buf)
	challenge := Challenge{
		ChallengeID: id,
		Username:    username,
		Purpose:     purpose,
		ExpHours:    expHours,
		ExpiresAt:   time.Now().Add(ChallengeTTL),
	}
	if err := m.DB.Create(&challenge).Error; err != nil {
		return "", fmt.Errorf("mfa: creating challenge: %w", err)
	}
	// Opportunistic cleanup so abandoned challenges do not accumulate.
	// Best-effort: a failure here must not fail the login.
	if err := m.DB.Unscoped().Where("expires_at < ?", time.Now().Add(-time.Hour)).Delete(&Challenge{}).Error; err != nil {
		log.Err(err).Msg("mfa: pruning expired challenges")
	}
	return id, nil
}

// GetChallenge returns a live challenge with the expected purpose.
func (m *Manager) GetChallenge(id, purpose string) (Challenge, error) {
	var challenge Challenge
	if id == "" {
		return challenge, ErrChallenge
	}
	err := m.DB.Where("challenge_id = ? AND purpose = ?", id, purpose).First(&challenge).Error
	if err != nil {
		return challenge, ErrChallenge
	}
	if challenge.ConsumedAt != nil || time.Now().After(challenge.ExpiresAt) {
		return challenge, ErrChallenge
	}
	return challenge, nil
}

// ConsumeChallenge marks a challenge used. It returns ErrChallenge if another
// request got there first, so a challenge can never mint two sessions.
func (m *Manager) ConsumeChallenge(id string) error {
	now := time.Now()
	res := m.DB.Model(&Challenge{}).
		Where("challenge_id = ? AND consumed_at IS NULL", id).
		Update("consumed_at", &now)
	if res.Error != nil {
		return fmt.Errorf("mfa: consuming challenge: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrChallenge
	}
	return nil
}

// SetChallengeSession attaches WebAuthn ceremony state (or a pending TOTP
// secret) to a challenge between its begin and finish steps.
func (m *Manager) SetChallengeSession(id, sessionData, pendingSecret string) error {
	updates := map[string]any{}
	if sessionData != "" {
		updates["session_data"] = sessionData
	}
	if pendingSecret != "" {
		updates["pending_secret"] = pendingSecret
	}
	if len(updates) == 0 {
		return nil
	}
	if err := m.DB.Model(&Challenge{}).Where("challenge_id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("mfa: updating challenge: %w", err)
	}
	return nil
}

// DeleteUser removes every factor belonging to a user. Called when the user
// row itself is deleted so credentials do not outlive the account.
func (m *Manager) DeleteUser(username string) error {
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("username = ?", username).Delete(&TOTPEnrollment{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("username = ?", username).Delete(&RecoveryCode{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("username = ?", username).Delete(&Credential{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Where("username = ?", username).Delete(&Challenge{}).Error
	})
}
