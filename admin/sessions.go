package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	"github.com/jmpsec/osctrl/users"
)

const sessionIDLen int = 64

// FIXME this can be configurable
const defaultMaxAge int = 60 * 60 * 2 // 2 hours
const defaultPath string = "/"
const defaultHTTPOnly bool = true
const defaultSecure bool = true
const defaultCookieName string = projectName

// SessionManager represent a session's store structure
type SessionManager struct {
	db      *gorm.DB
	Codecs  []securecookie.Codec
	Options *sessions.Options
}

// sessionValues to keep session values
type sessionValues map[interface{}]interface{}

// contextValue to hold session data in the context
type contextValue map[string]string

// contextKey to help with the context key, to pass session data
type contextKey string

// UserSession as abstraction of a session
type UserSession struct {
	gorm.Model
	Username  string
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	Cookie    string        `gorm:"index"`
	Values    sessionValues `gorm:"-"`
}

// CreateSessionManager creates a new session store in the DB and initialize the tables
func CreateSessionManager(db *gorm.DB) *SessionManager {
	storeKey := securecookie.GenerateRandomKey(sessionIDLen)
	st := &SessionManager{
		db:     db,
		Codecs: securecookie.CodecsFromPairs(storeKey),
		Options: &sessions.Options{
			Path:     defaultPath,
			MaxAge:   defaultMaxAge,
			Secure:   defaultSecure,
			HttpOnly: defaultHTTPOnly,
		},
	}
	// table user_sessions
	if err := db.AutoMigrate(&UserSession{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (user_sessions): %v", err)
	}
	return st
}

// CheckAuth to verify if a session exists/is valid
func (sm *SessionManager) CheckAuth(r *http.Request) (bool, UserSession) {
	cookie, err := r.Cookie(defaultCookieName)
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
	if err := sm.db.Where("cookie = ?", cookie).Where("expires_at > ?", gorm.NowFunc()).First(&s).Error; err != nil {
		return s, err
	}
	if err := securecookie.DecodeMulti(defaultCookieName, cookie, &s.Values, sm.Codecs...); err != nil {
		return s, err
	}
	return s, nil
}

// GetByUsername returns all the existing sessions for the given username
func (sm *SessionManager) GetByUsername(username string) ([]UserSession, error) {
	var sessionsRaw []UserSession
	if err := sm.db.Where("username = ?", username).Error; err != nil {
		return sessionsRaw, err
	}
	var sessionsFinal []UserSession
	for _, s := range sessionsRaw {
		if err := securecookie.DecodeMulti(defaultCookieName, s.Cookie, &s.Values, sm.Codecs...); err != nil {
			return sessionsFinal, err
		}
		sessionsFinal = append(sessionsFinal, s)
	}
	return sessionsFinal, nil
}

// New creates a session with name without adding it to the registry.
func (sm *SessionManager) New(r *http.Request, username string, admin bool) (UserSession, error) {
	session := UserSession{
		Username:  username,
		IPAddress: r.Header.Get("X-Real-IP"),
		UserAgent: r.Header.Get("User-Agent"),
		ExpiresAt: time.Now().Add(time.Duration(defaultMaxAge) * time.Second),
	}
	values := make(sessionValues)
	values["auth"] = true
	values["admin"] = admin
	values["username"] = username
	values["csrftoken"] = generateCSRF()
	session.Values = values
	cookie, err := securecookie.EncodeMulti(defaultCookieName, session.Values, sm.Codecs...)
	if err != nil {
		return UserSession{}, err
	}
	session.Cookie = cookie
	if sm.db.NewRecord(session) {
		if err := sm.db.Create(&session).Error; err != nil {
			return UserSession{}, fmt.Errorf("Create UserSession %v", err)
		}
	} else {
		return UserSession{}, fmt.Errorf("db.NewRecord did not return true")
	}
	return session, nil
}

// Destroy session expires it and it will be cleaned up
func (sm *SessionManager) Destroy(r *http.Request) error {
	if cookie, err := r.Cookie(defaultCookieName); err == nil {
		s, err := sm.Get(cookie.Value)
		if err != nil {
			return err
		}
		if err := sm.db.Model(&s).Update("expires_at", time.Now().Add(-1*time.Second)).Error; err != nil {
			return fmt.Errorf("Update %v", err)
		}
	}
	return nil
}

// Save session and set cookie header
func (sm *SessionManager) Save(r *http.Request, w http.ResponseWriter, user users.AdminUser) (UserSession, error) {
	var s UserSession
	if cookie, err := r.Cookie(defaultCookieName); err != nil {
		s, err = sm.New(r, user.Username, user.Admin)
		if err != nil {
			return s, err
		}
	} else {
		s, err = sm.Get(cookie.Value)
		if err != nil {
			s, err = sm.New(r, user.Username, user.Admin)
			if err != nil {
				return s, err
			}
		}
		if s.Username != user.Username {
			return s, fmt.Errorf("Invalid user session (%s)", s.Username)
		}
	}
	http.SetCookie(w, sessions.NewCookie(defaultCookieName, s.Cookie, sm.Options))

	return s, nil
}

// Cleanup deletes expired sessions
func (sm *SessionManager) Cleanup() {
	sm.db.Delete(&UserSession{}, "expires_at <= ?", gorm.NowFunc())
}
