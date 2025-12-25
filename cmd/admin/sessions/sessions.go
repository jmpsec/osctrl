package sessions

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const sessionIDLen int = 64

// FIXME this can be configurable
const defaultMaxAge int = 60 * 60 * 2 // 2 hours
const defaultPath string = "/"
const defaultHTTPOnly bool = true
const defaultSecure bool = true

// SessionManager represent a session's store structure
type SessionManager struct {
	db         *gorm.DB
	Codecs     []securecookie.Codec
	Options    *sessions.Options
	CookieName string
}

const (
	AdminLevel string = "admin"
	UserLevel  string = "user"
	QueryLevel string = "query"
	CarveLevel string = "carve"
)

const (
	CtxUser    = "user"
	CtxEmail   = "email"
	CtxCSRF    = "csrftoken"
	CtxSession = "session"
)

// sessionValues to keep session values
type SessionValues map[interface{}]interface{}

// contextValue to hold session data in the context
type ContextValue map[string]string

// contextKey to help with the context key, to pass session data
type ContextKey string

// UserSession as abstraction of a session
type UserSession struct {
	gorm.Model
	Username  string
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	Cookie    string        `gorm:"index"`
	Values    SessionValues `gorm:"-"`
}

// CreateSessionManager creates a new session store in the DB and initialize the tables
func CreateSessionManager(db *gorm.DB, name, sKey string) *SessionManager {
	storeKey := []byte(sKey)
	if sKey == "" {
		storeKey = securecookie.GenerateRandomKey(sessionIDLen)
	}
	st := &SessionManager{
		db:     db,
		Codecs: securecookie.CodecsFromPairs(storeKey),
		Options: &sessions.Options{
			Path:     defaultPath,
			MaxAge:   defaultMaxAge,
			Secure:   defaultSecure,
			HttpOnly: defaultHTTPOnly,
		},
		CookieName: name,
	}
	// table user_sessions
	if err := db.AutoMigrate(&UserSession{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (user_sessions): %v", err)
	}
	return st
}

// CheckAuth to verify if a session exists/is valid
func (sm *SessionManager) CheckAuth(r *http.Request) (bool, UserSession) {
	cookie, err := r.Cookie(sm.CookieName)
	if err != nil {
		return false, UserSession{}
	}
	s, err := sm.Get(cookie.Value)
	if err != nil {
		return false, UserSession{}
	}
	return s.Values["auth"].(bool), s
}

// Get returns a non-expired existing session for the given cookie
func (sm *SessionManager) Get(cookie string) (UserSession, error) {
	var s UserSession
	if err := sm.db.Where("cookie = ?", cookie).Where("expires_at > ?", time.Now().Local()).First(&s).Error; err != nil {
		return s, err
	}
	if err := securecookie.DecodeMulti(sm.CookieName, cookie, &s.Values, sm.Codecs...); err != nil {
		return s, err
	}
	return s, nil
}

// GetByUsername returns all the existing sessions for the given username
func (sm *SessionManager) GetByUsername(username string) ([]UserSession, error) {
	var sessionsRaw []UserSession
	if err := sm.db.Where("username = ?", username).First(&sessionsRaw).Error; err != nil {
		return sessionsRaw, err
	}
	var sessionsFinal []UserSession
	for _, s := range sessionsRaw {
		if err := securecookie.DecodeMulti(sm.CookieName, s.Cookie, &s.Values, sm.Codecs...); err != nil {
			return sessionsFinal, err
		}
		sessionsFinal = append(sessionsFinal, s)
	}
	return sessionsFinal, nil
}

// New creates a session with name without adding it to the registry.
func (sm *SessionManager) New(r *http.Request, username string) (UserSession, error) {
	session := UserSession{
		Username:  username,
		IPAddress: utils.GetIP(r),
		UserAgent: r.Header.Get(utils.UserAgent),
		ExpiresAt: time.Now().Add(time.Duration(defaultMaxAge) * time.Second),
	}
	values := make(SessionValues)
	values["auth"] = true
	values[CtxUser] = username
	values[CtxCSRF] = GenerateCSRF()
	session.Values = values
	cookie, err := securecookie.EncodeMulti(sm.CookieName, session.Values, sm.Codecs...)
	if err != nil {
		return UserSession{}, err
	}
	session.Cookie = cookie
	if err := sm.db.Create(&session).Error; err != nil {
		return UserSession{}, fmt.Errorf("create UserSession %w", err)
	}
	return session, nil
}

// Destroy session expires it and it will be cleaned up
func (sm *SessionManager) Destroy(r *http.Request) error {
	if cookie, err := r.Cookie(sm.CookieName); err == nil {
		s, err := sm.Get(cookie.Value)
		if err != nil {
			return err
		}
		if err := sm.db.Model(&s).Update("expires_at", time.Now().Add(-1*time.Second)).Error; err != nil {
			return fmt.Errorf("update %w", err)
		}
	}
	return nil
}

// Save session and set cookie header
func (sm *SessionManager) Save(r *http.Request, w http.ResponseWriter, user users.AdminUser) (UserSession, error) {
	var s UserSession
	if cookie, err := r.Cookie(sm.CookieName); err != nil {
		s, err = sm.New(r, user.Username)
		if err != nil {
			return s, err
		}
	} else {
		s, err = sm.Get(cookie.Value)
		if err != nil {
			s, err = sm.New(r, user.Username)
			if err != nil {
				return s, err
			}
		}
		if s.Username != user.Username {
			return s, fmt.Errorf("invalid user session (%s)", s.Username)
		}
	}
	http.SetCookie(w, sessions.NewCookie(sm.CookieName, s.Cookie, sm.Options))

	return s, nil
}

// Cleanup deletes expired sessions
func (sm *SessionManager) Cleanup() {
	sm.db.Delete(&UserSession{}, "expires_at <= ?", time.Now().Local())
}

// Function to generate a secure CSRF token
func GenerateCSRF() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Helper to convert permissions for a user to a level for context
func LevelPermissions(user users.AdminUser, access users.EnvAccess) string {
	if user.Admin {
		return AdminLevel
	}
	// Check for query access
	if access.Query {
		return QueryLevel
	}
	// Check for carve access
	if access.Carve {
		return CarveLevel
	}
	// At this point, no access granted
	return UserLevel
}

// Helper to check if the CSRF token is valid
func CheckCSRFToken(ctxToken, receivedToken string) bool {
	return (strings.TrimSpace(ctxToken) == strings.TrimSpace(receivedToken))
}
