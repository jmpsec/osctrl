package sessions

// Based on https://github.com/wader/gormstore

/*
Simplest form:

	store := gormstore.New(gorm.Open(...), []byte("secret-hash-key"))

All options:

	store := gormstore.NewOptions(
		gorm.Open(...), // *gorm.DB
		gormstore.Options{
			TableName: "sessions",  // "sessions" is default
			SkipCreateTable: false, // false is default
		},
		[]byte("secret-hash-key"),      // 32 or 64 bytes recommended, required
		[]byte("secret-encyption-key")) // nil, 16, 24 or 32 bytes, optional

		// some more settings, see sessions.Options
		store.SessionOpts.Secure = true
		store.SessionOpts.HttpOnly = true
		store.SessionOpts.MaxAge = 60 * 60 * 24 * 60

If you want periodic cleanup of expired sessions:

		quit := make(chan struct{})
		go store.PeriodicCleanup(1*time.Hour, quit)

For more information about the keys see https://github.com/gorilla/securecookie

For API to use in HTTP handlers see https://github.com/gorilla/sessions
*/

import (
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
)

const sessionIDLen int = 64
const defaultMaxAge int = 60 * 60 * 24 * 30 // 30 days
const defaultPath string = "/"
const defaultHTTPOnly bool = true
const defaultSecure bool = true

// SessionManager represent a session's store structure
type SessionManager struct {
	db      *gorm.DB
	Codecs  []securecookie.Codec
	Options *sessions.Options
}

type userSession struct {
	gorm.Model
	Username   string
	Admin      bool
	CSRF       string
	IPAddress  string
	UserAgent  string
	LastAccess time.Time
	ExpiresAt  time.Time
	Data       string
}

// New creates a new gormstore session
func New(db *gorm.DB, keyPairs ...[]byte) *SessionManager {
	st := &SessionManager{
		db:     db,
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:     defaultPath,
			MaxAge:   defaultMaxAge,
			Secure:   defaultSecure,
			HttpOnly: defaultHTTPOnly,
		},
	}
	st.db.AutoMigrate(&userSession{})
	return st
}

/*
// Get returns a session for the given name after adding it to the registry.
func (st *Store) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(st, name)
}

// New creates a session with name without adding it to the registry.
func (st *Store) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(st, name)
	opts := *st.Options
	session.Options = &opts

	st.MaxAge(st.Options.MaxAge)

	// try fetch from db if there is a cookie
	if cookie, err := r.Cookie(name); err == nil {
		if err := securecookie.DecodeMulti(name, cookie.Value, &session.ID, st.Codecs...); err != nil {
			return session, nil
		}
		s := &userSession{}
		if err := st.db.Where("id = ? AND expires_at > ?", session.ID, gorm.NowFunc()).First(s).Error; err != nil {
			return session, nil
		}
		if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values, st.Codecs...); err != nil {
			return session, nil
		}
	}

	return session, nil
}

// Save session and set cookie header
/*
func (st *Store) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	s, _ := environment.Get(r, environmentKey(session.Name())).(*gormSession)

	// delete if max age is < 0
	if session.Options.MaxAge < 0 {
		if s != nil {
			if err := st.db.Delete(s).Error; err != nil {
				return err
			}
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	data, err := securecookie.EncodeMulti(session.Name(), session.Values, st.Codecs...)
	if err != nil {
		return err
	}
	now := time.Now()
	expire := now.Add(time.Second * time.Duration(session.Options.MaxAge))

	if s == nil {
		// generate random session ID key suitable for storage in the db
		session.ID = strings.TrimRight(
			base32.StdEncoding.EncodeToString(
				securecookie.GenerateRandomKey(sessionIDLen)), "=")
		s = &userSession{
			Data:      data,
		}
		if err := st.db.Create(s).Error; err != nil {
			return err
		}
	} else {
		s.Data = data
		s.UpdatedAt = now
		s.ExpiresAt = expire
		if err := st.db.Save(s).Error; err != nil {
			return err
		}
	}

	// set session id cookie
	id, err := securecookie.EncodeMulti(session.Name(), session.ID, st.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), id, session.Options))

	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting
// Options.MaxAge = -1 for that session.
func (st *Store) MaxAge(age int) {
	st.Options.MaxAge = age
	for _, codec := range st.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default is 4096 (default for securecookie)
func (st *Store) MaxLength(l int) {
	for _, c := range st.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Cleanup deletes expired sessions
func (st *Store) Cleanup() {
	st.db.Delete(&userSession{}, "expires_at <= ?", gorm.NowFunc())
}

// PeriodicCleanup runs Cleanup every interval. Close quit channel to stop.
func (st *Store) PeriodicCleanup(interval time.Duration, quit <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			st.Cleanup()
		case <-quit:
			return
		}
	}
}
*/
