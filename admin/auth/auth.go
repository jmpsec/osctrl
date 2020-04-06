package auth

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
)

// AdminAuth to handle authentication for admin
type AdminAuth struct {
	Users    *users.UserManager
	Sessions *sessions.SessionManager
}

type AuthOption func(*AdminAuth)

func WithSessions(sessions *sessions.SessionManager) AuthOption {
	return func(a *AdminAuth) {
		a.Sessions = sessions
	}
}

func WithUsers(users *users.UserManager) AuthOption {
	return func(a *AdminAuth) {
		a.Users = users
	}
}

// CreateAdminAuth to initialize the Admin handlers struct
func CreateAdminAuth(opts ...AuthOption) *AdminAuth {
	a := &AdminAuth{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// LevelPermissions to convert permissions for a user to a level for context
func (a *AdminAuth) LevelPermissions(user users.AdminUser) string {
	if user.Admin {
		return sessions.AdminLevel
	}
	perms, err := a.Users.ConvertPermissions(user.Permissions.RawMessage)
	if err != nil {
		log.Printf("error converting permissions %v", err)
		return sessions.UserLevel
	}
	// Check for query access
	if perms.Query {
		return sessions.QueryLevel
	}
	// Check for carve access
	if perms.Carve {
		return sessions.CarveLevel
	}
	// At this point, no access granted
	return sessions.UserLevel
}

// Handler to check access to a resource based on the authentication enabled
func (a *AdminAuth) HandlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case settings.AuthDB:
			// Check if user is already authenticated
			authenticated, session := a.Sessions.CheckAuth(r)
			if !authenticated {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Set middleware values
			s := make(sessions.ContextValue)
			s[sessions.CtxUser] = session.Username
			s[sessions.CtxCSRF] = session.Values[sessions.CtxCSRF].(string)
			s[sessions.CtxLevel] = session.Values[sessions.CtxLevel].(string)
			ctx := context.WithValue(r.Context(), sessions.ContextKey("session"), s)
			// Update metadata for the user
			if err := a.Users.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s["csrftoken"]); err != nil {
				log.Printf("error updating metadata for user %s: %v", session.Username, err)
			}
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthSAML:
			if samlMiddleware.IsAuthorized(r) {
				cookiev, err := r.Cookie(samlConfig.TokenName)
				if err != nil {
					log.Printf("error extracting JWT data: %v", err)
					http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
					return
				}
				jwtdata, err := parseJWTFromCookie(samlData.KeyPair, cookiev.Value)
				if err != nil {
					log.Printf("error parsing JWT: %v", err)
					http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
					return
				}
				// Check if user is already authenticated
				authenticated, session := a.Sessions.CheckAuth(r)
				if !authenticated {
					// Create user if it does not exist
					if !a.Users.Exists(jwtdata.Username) {
						log.Printf("user not found: %s", jwtdata.Username)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					u, err := a.Users.Get(jwtdata.Username)
					if err != nil {
						log.Printf("error getting user %s: %v", jwtdata.Username, err)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					// Create new session
					session, err = a.Sessions.Save(r, w, u)
					if err != nil {
						log.Printf("session error: %v", err)
						http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
						return
					}
				}
				// Set middleware values
				s := make(sessions.ContextValue)
				s[sessions.CtxUser] = session.Username
				s[sessions.CtxCSRF] = session.Values[sessions.CtxCSRF].(string)
				s[sessions.CtxLevel] = session.Values[sessions.CtxLevel].(string)
				ctx := context.WithValue(r.Context(), sessions.ContextKey("session"), s)
				// Update metadata for the user
				err = a.Users.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s["csrftoken"])
				if err != nil {
					log.Printf("error updating metadata for user %s: %v", session.Username, err)
				}
				// Access granted
				samlMiddleware.RequireAccount(h).ServeHTTP(w, r.WithContext(ctx))
			} else {
				samlMiddleware.RequireAccount(h).ServeHTTP(w, r)
			}
		case settings.AuthHeaders:
			username := r.Header.Get(headersConfig.TrustedPrefix + headersConfig.UserName)
			email := r.Header.Get(headersConfig.TrustedPrefix + headersConfig.Email)
			groups := strings.Split(r.Header.Get(headersConfig.TrustedPrefix+headersConfig.Groups), ",")
			fullname := r.Header.Get(headersConfig.TrustedPrefix + headersConfig.DisplayName)
			// A username is required to use this system
			if username == "" {
				http.Redirect(w, r, forbiddenPath, http.StatusBadRequest)
				return
			}
			// Set middleware values
			s := make(sessions.ContextValue)
			s[sessions.CtxUser] = username
			s[sessions.CtxCSRF] = generateCSRF()
			for _, group := range groups {
				if group == headersConfig.AdminGroup {
					s[sessions.CtxLevel] = sessions.AdminLevel
					// We can break because there is no greater permission level
					break
				} else if group == headersConfig.UserGroup {
					s[sessions.CtxLevel] = sessions.UserLevel
					// We can't break because we might still find a higher permission level
				}
			}
			// This user didn't present a group that has permission to use the service
			if _, ok := s[sessions.CtxLevel]; !ok {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			newUser, err := a.Users.New(username, "", email, fullname, (s[sessions.CtxLevel] == sessions.AdminLevel))
			if err != nil {
				log.Printf("Error with new user %s: %v", username, err)
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			if err := a.Users.Create(newUser); err != nil {
				log.Printf("Error creating user %s: %v", username, err)
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// _, session := sessionsmgr.CheckAuth(r)
			// s["csrftoken"] = session.Values["csrftoken"].(string)
			ctx := context.WithValue(r.Context(), sessions.ContextKey("session"), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

// Helper to prepare context based on the user
func prepareContext(user users.AdminUser) sessions.ContextValue {
	s := make(sessions.ContextValue)
	s[sessions.CtxUser] = user.Username
	s[sessions.CtxEmail] = user.Email
	s[sessions.CtxCSRF] = user.CSRFToken
	s[sessions.CtxLevel] = levelPermissions(user)
	return s
}

// Helper to parse JWT tokens because the SAML library is total garbage
func parseJWTFromCookie(keypair tls.Certificate, cookie string) (JWTData, error) {
	type TokenClaims struct {
		jwt.StandardClaims
		Attributes map[string][]string `json:"attr"`
	}
	tokenClaims := TokenClaims{}
	token, err := jwt.ParseWithClaims(cookie, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
		secretBlock := x509.MarshalPKCS1PrivateKey(keypair.PrivateKey.(*rsa.PrivateKey))
		return secretBlock, nil
	})
	if err != nil || !token.Valid {
		return JWTData{}, err
	}
	return JWTData{
		Subject:  tokenClaims.Subject,
		Email:    tokenClaims.Attributes["mail"][0],
		Display:  tokenClaims.Attributes["displayName"][0],
		Username: tokenClaims.Attributes["sAMAccountName"][0],
	}, nil
}
