package users

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	DefaultTokenIssuer = "osctrl"
	// ActionAdd as action to add a user
	ActionAdd string = "add"
	// ActionEdit as action to edit a user
	ActionEdit string = "edit"
	// ActionRemove as action to remove a user
	ActionRemove string = "remove"
)

// AdminUser to hold all users
type AdminUser struct {
	gorm.Model
	Username      string `gorm:"index"`
	Email         string
	Fullname      string
	PassHash      string `json:"-"`
	APIToken      string `json:"-"`
	TokenExpire   time.Time
	Admin         bool
	Service       bool
	UUID          string
	CSRFToken     string `json:"-"`
	LastIPAddress string
	LastUserAgent string
	LastAccess    time.Time
	LastTokenUse  time.Time
	EnvironmentID uint
}

// TokenClaims to hold user claims when using JWT
type TokenClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// UserManager have all users of the system
type UserManager struct {
	DB        *gorm.DB
	JWTConfig *config.YAMLConfigurationJWT
}

// MinJWTSecretBytes is the minimum acceptable length of the HMAC JWT secret
// (RFC 7518 §3.2 recommends a key at least as wide as the hash output for
// HS256 ⇒ 32 bytes). Generate one with: openssl rand -base64 48
const MinJWTSecretBytes = 32

// CreateUserManager to initialize the users struct and tables
func CreateUserManager(backend *gorm.DB, jwtconfig *config.YAMLConfigurationJWT) *UserManager {
	// JWT secret must be present and long enough for HS256.
	if jwtconfig.JWTSecret == "" {
		log.Fatal().Msgf("JWT Secret can not be empty")
	}
	if len(jwtconfig.JWTSecret) < MinJWTSecretBytes {
		log.Fatal().Msgf("JWT Secret too short: have %d bytes, need >= %d. Generate one with: openssl rand -base64 48",
			len(jwtconfig.JWTSecret), MinJWTSecretBytes)
	}
	u := &UserManager{DB: backend, JWTConfig: jwtconfig}
	// table admin_users
	if err := backend.AutoMigrate(&AdminUser{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (admin_users): %v", err)
	}
	// table user_permissions
	if err := backend.AutoMigrate(&UserPermission{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (user_permissions): %v", err)
	}
	return u
}

// BcryptCost is the bcrypt work factor for password hashing. 12 is the
// 2026 commodity-CPU recommendation; bcrypt.DefaultCost is 10.
const BcryptCost = 12

// HashTextWithSalt to hash text before store it
func (m *UserManager) HashTextWithSalt(text string) (string, error) {
	saltedBytes := []byte(text)
	hashedBytes, err := bcrypt.GenerateFromPassword(saltedBytes, BcryptCost)
	if err != nil {
		return "", err
	}
	hash := string(hashedBytes)
	return hash, nil
}

// HashPasswordWithSalt to hash a password before store it
func (m *UserManager) HashPasswordWithSalt(password string) (string, error) {
	return m.HashTextWithSalt(password)
}

// CheckLoginCredentials matches password hashes and, on a successful
// match, opportunistically re-hashes the password at the current
// BcryptCost when the stored hash is below it. Users created under an
// older cost migrate transparently on their next login. The rehash
// failure is non-fatal — login succeeds even if the rehash write
// fails (next login retries).
func (m *UserManager) CheckLoginCredentials(username, password string) (bool, AdminUser) {
	// Check if we should include service users
	user, err := m.Get(username)
	if err != nil {
		return false, AdminUser{}
	}
	// Check for hash matching
	p := []byte(password)
	existing := []byte(user.PassHash)
	if err := bcrypt.CompareHashAndPassword(existing, p); err != nil {
		return false, AdminUser{}
	}
	// Successful login — rehash if the stored cost is below current.
	if cost, cerr := bcrypt.Cost(existing); cerr == nil && cost < BcryptCost {
		if newHash, herr := m.HashPasswordWithSalt(password); herr == nil {
			if uerr := m.DB.Model(&user).Update("pass_hash", newHash).Error; uerr != nil {
				log.Err(uerr).Msgf("rehash-on-login: failed to persist new pass_hash for %s", username)
			} else {
				user.PassHash = newHash
			}
		} else {
			log.Err(herr).Msgf("rehash-on-login: bcrypt cost upgrade failed for %s", username)
		}
	}
	return true, user
}

// CreateToken to create a new JWT token for a given user
func (m *UserManager) CreateToken(username, issuer string, expHours int) (string, time.Time, error) {
	tDuration := time.Duration(expHours)
	if expHours == 0 {
		tDuration = time.Duration(m.JWTConfig.HoursToExpire)
	}
	expirationTime := time.Now().Add(time.Hour * tDuration)
	// Create the JWT claims, which includes the username, level and expiry time
	claims := &TokenClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    issuer,
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString([]byte(m.JWTConfig.JWTSecret))
	if err != nil {
		return "", time.Now(), err
	}
	return tokenString, expirationTime, nil
}

// CheckToken to verify if a token used is valid.
// Pins the signing algorithm to HMAC so an attacker cannot swap to `alg:none`
// or RS256-with-public-key (RS-vs-HS confusion) — defense-in-depth on top of
// the underlying library's own mitigations.
func (m *UserManager) CheckToken(jwtSecret, tokenStr string) (TokenClaims, bool) {
	claims := &TokenClaims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected jwt signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		log.Err(err).Msg("error parsing token claims")
		return *claims, false
	}
	if !tkn.Valid {
		log.Info().Msg("token not valid")
		return *claims, false
	}
	return *claims, true
}

// Get user by username including service users
func (m *UserManager) Get(username string) (AdminUser, error) {
	var user AdminUser
	if err := m.DB.Where("username = ?", username).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Get user by username and by environment ID, including service users
func (m *UserManager) GetByEnvID(username string, envID uint) (AdminUser, error) {
	var user AdminUser
	if err := m.DB.Where("username = ? AND environment_id = ?", username, envID).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Get user by username and service
func (m *UserManager) GetWithService(username string, service bool) (AdminUser, error) {
	var user AdminUser
	if err := m.DB.Where("username = ? AND service = ?", username, service).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Get user by username, service and environment ID
func (m *UserManager) GetWithServiceByEnvID(username string, service bool, envID uint) (AdminUser, error) {
	var user AdminUser
	if err := m.DB.Where("username = ? AND service = ? AND environment_id = ?", username, service, envID).First(&user).Error; err != nil {
		return user, err
	}
	return user, nil
}

// Create new user
func (m *UserManager) Create(user AdminUser) error {
	if err := m.DB.Create(&user).Error; err != nil {
		return fmt.Errorf("Create AdminUser %w", err)
	}
	return nil
}

// New empty user
func (m *UserManager) New(username, password, email, fullname string, admin, service bool) (AdminUser, error) {
	if !m.Exists(username) {
		passhash, err := m.HashPasswordWithSalt(password)
		if err != nil {
			return AdminUser{}, err
		}
		return AdminUser{
			Username: username,
			PassHash: passhash,
			UUID:     utils.GenUUID(),
			Admin:    admin,
			Service:  service,
			Email:    email,
			Fullname: fullname,
		}, nil
	}
	return AdminUser{}, fmt.Errorf("%s already exists", username)
}

// Exists checks if user exists
func (m *UserManager) Exists(username string) bool {
	var results int64
	m.DB.Model(&AdminUser{}).Where("username = ?", username).Count(&results)
	return (results > 0)
}

// ExistsGet checks if user exists and returns the user
func (m *UserManager) ExistsGet(username string) (bool, AdminUser) {
	user, err := m.Get(username)
	if err != nil {
		return false, AdminUser{}
	}
	return true, user
}

// IsAdmin checks if user is an admin
func (m *UserManager) IsAdmin(username string) bool {
	var results int64
	m.DB.Model(&AdminUser{}).Where("username = ? AND admin = ?", username, true).Count(&results)
	return (results > 0)
}

// CountAdmins returns the number of active admin (Admin=true) users.
// Used by the permissions API to refuse demoting the last super-admin
// (which would lock the system out — no remaining super-admin = no
// one can promote anyone else).
func (m *UserManager) CountAdmins() (int64, error) {
	var results int64
	if err := m.DB.Model(&AdminUser{}).Where("admin = ?", true).Count(&results).Error; err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return results, nil
}

// ChangeAdmin to modify the admin setting for a user
func (m *UserManager) ChangeAdmin(username string, admin bool) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if admin != user.Admin {
		if err := m.DB.Model(&user).Updates(map[string]interface{}{"admin": admin}).Error; err != nil {
			return err
		}
	}
	return nil
}

// ChangeService to modify the service setting for a user
func (m *UserManager) ChangeService(username string, service bool) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if service != user.Service {
		if err := m.DB.Model(&user).Updates(map[string]interface{}{"service": service}).Error; err != nil {
			return err
		}
	}
	return nil
}

// All get all users
func (m *UserManager) All() ([]AdminUser, error) {
	var users []AdminUser
	if err := m.DB.Find(&users).Error; err != nil {
		return users, err
	}
	return users, nil
}

// GenericAllService get all users with a specific service
func (m *UserManager) GenericAllService(service bool) ([]AdminUser, error) {
	var users []AdminUser
	if err := m.DB.Where("service = ?", service).Find(&users).Error; err != nil {
		return users, err
	}
	return users, nil
}

// AllService get all service users
func (m *UserManager) AllService() ([]AdminUser, error) {
	return m.GenericAllService(true)
}

// AllNonService get all non-service users
func (m *UserManager) AllNonService() ([]AdminUser, error) {
	return m.GenericAllService(false)
}

// Delete user by username
func (m *UserManager) Delete(username string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if err := m.DB.Unscoped().Delete(&user).Error; err != nil {
		return fmt.Errorf("Delete %w", err)
	}
	return nil
}

// ChangePassword for user by username
func (m *UserManager) ChangePassword(username, password string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	passhash, err := m.HashPasswordWithSalt(password)
	if err != nil {
		return err
	}
	if passhash != user.PassHash {
		if err := m.DB.Model(&user).Update("pass_hash", passhash).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// UpdateToken for user by username
func (m *UserManager) UpdateToken(username, token string, exp time.Time) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if token != user.APIToken {
		// Rotation also clears CSRFToken so the SPA's old non-HttpOnly
		// CSRF cookie value stops matching the server-side binding —
		// stops a stale CSRFToken from outliving the JWT it was minted
		// alongside. The SPA must re-login (which writes a fresh
		// CSRFToken via UpdateMetadata) before mutations work again.
		//
		if err := m.DB.Model(&user).Updates(map[string]interface{}{
			"api_token":    token,
			"token_expire": exp,
			"csrf_token":   "",
		}).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ClearToken empties the user's APIToken and CSRFToken so any existing
// JWT + CSRF cookie pair for them stops validating. Used by DELETE
// /api/v1/users/{username}/token. We use a map-update so the empty
// strings actually land (GORM's struct-Updates skips zero-value fields).
func (m *UserManager) ClearToken(username string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if err := m.DB.Model(&user).Updates(map[string]interface{}{
		"api_token":    "",
		"token_expire": time.Time{},
		"csrf_token":   "",
	}).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	return nil
}

// ChangeEmail for user by username
func (m *UserManager) ChangeEmail(username, email string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if email != user.Email {
		if err := m.DB.Model(&user).Update("email", email).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// ChangeFullname for user by username
func (m *UserManager) ChangeFullname(username, fullname string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if fullname != user.Fullname {
		if err := m.DB.Model(&user).Update("fullname", fullname).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// UpdateMetadata updates IP, User Agent and Last Access for a given user
func (m *UserManager) UpdateMetadata(ipaddress, useragent, username, csrftoken string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if err := m.DB.Model(&user).Updates(
		AdminUser{
			LastIPAddress: ipaddress,
			LastUserAgent: useragent,
			CSRFToken:     csrftoken,
			LastAccess:    time.Now(),
		}).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	return nil
}

// UpdateTokenIPAddress updates IP and Last Access for a user's token
func (m *UserManager) UpdateTokenIPAddress(ipaddress, username string) error {
	user, err := m.Get(username)
	if err != nil {
		return fmt.Errorf("error getting user %w", err)
	}
	if err := m.DB.Model(&user).Updates(
		AdminUser{
			LastIPAddress: ipaddress,
			LastTokenUse:  time.Now(),
		}).Error; err != nil {
		return fmt.Errorf("update %w", err)
	}
	return nil
}
