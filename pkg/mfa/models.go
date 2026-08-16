package mfa

import (
	"time"

	"gorm.io/gorm"
)

// TOTPEnrollment is the authenticator-app factor for one user. A row exists
// from the moment enrollment starts; Confirmed flips to true only once the
// user has echoed back a valid code, so an abandoned enrollment never locks
// anyone out.
type TOTPEnrollment struct {
	gorm.Model
	Username string `gorm:"uniqueIndex"`
	// Secret is the base32 shared secret. It is as sensitive as a password
	// hash — anyone holding it can mint valid codes — so it is never
	// returned by the API after enrollment completes.
	Secret    string
	Confirmed bool
	// LastStep is the most recent RFC 6238 step this user authenticated
	// with, so the same code cannot be replayed inside its window.
	LastStep int64
}

func (TOTPEnrollment) TableName() string { return "user_mfa_totp" }

// RecoveryCode is one single-use code. Rows are kept after use so the UI can
// report how many are left and the audit trail shows a code was burned.
type RecoveryCode struct {
	gorm.Model
	Username string `gorm:"index"`
	CodeHash string
	UsedAt   *time.Time
}

func (RecoveryCode) TableName() string { return "user_mfa_recovery_codes" }

// Credential is one registered WebAuthn authenticator: a passkey, a platform
// authenticator (Touch ID, Windows Hello) or a roaming security key.
type Credential struct {
	gorm.Model
	Username string `gorm:"index"`
	// Name is the operator-supplied label ("YubiKey 5C", "iPhone").
	Name string
	// CredentialID is stored base64url-encoded rather than as raw bytes:
	// a unique index on a blob column needs a prefix length on MySQL, and
	// the SPA needs the string form anyway to address the row.
	CredentialID    string `gorm:"uniqueIndex"`
	PublicKey       []byte
	AttestationType string
	AAGUID          []byte
	SignCount       uint32
	// CloneWarning is set when an authenticator's signature counter goes
	// backwards, which suggests a cloned credential. Kept as a flag rather
	// than a hard failure — some authenticators legitimately keep the
	// counter at zero.
	CloneWarning   bool
	Transports     string
	BackupEligible bool
	BackupState    bool
	LastUsedAt     *time.Time
}

func (Credential) TableName() string { return "user_mfa_credentials" }

// Challenge ties the two halves of a login (or a WebAuthn ceremony) together.
// The first factor succeeding does not create a session; it creates one of
// these, and only presenting a second factor against it mints a token.
//
// Rows are single-use and short-lived, which is what makes a stolen challenge
// id worthless on its own: it still requires the second factor.
type Challenge struct {
	gorm.Model
	ChallengeID string `gorm:"uniqueIndex"`
	Username    string `gorm:"index"`
	Purpose     string
	// SessionData is the go-webauthn session blob (JSON) for ceremonies
	// that have one; empty for TOTP and recovery-code challenges.
	SessionData string `gorm:"type:text"`
	// PendingSecret carries a TOTP secret through a forced enrollment at
	// login, before the user has proven they can generate codes from it.
	PendingSecret string
	// ExpHours is the token lifetime the client asked for in the first
	// step, so the second step can honor it.
	ExpHours   int
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

func (Challenge) TableName() string { return "user_mfa_challenges" }

// Challenge purposes.
const (
	// PurposeLogin — first factor passed, waiting for the second.
	PurposeLogin string = "login"
	// PurposeEnroll — first factor passed but the deployment requires MFA
	// and this user has none, so they must enroll before getting a session.
	PurposeEnroll string = "enroll"
	// PurposeRegister — an authenticated user is registering a new WebAuthn
	// credential from their profile.
	PurposeRegister string = "register"
)

// ChallengeTTL bounds how long a half-finished login may sit. Long enough to
// find a phone and read a code, short enough that an abandoned challenge is
// not a standing invitation.
const ChallengeTTL = 5 * time.Minute
