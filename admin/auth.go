package main

import (
	"context"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
)

const (
	adminLevel string = "admin"
	userLevel  string = "user"
	queryLevel string = "query"
	carveLevel string = "carve"
)

// Using the default name for the cookie in SAML:
// https://github.com/crewjam/saml/blob/main/samlsp/session_cookie.go#L11
const (
	authCookieName = "token"
)

// Handler to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case settings.AuthDB:
			// Check if user is already authenticated
			authenticated, session := sessionsmgr.CheckAuth(r)
			if !authenticated {
				http.Redirect(w, r, loginPath, http.StatusFound)
				return
			}
			// Set middleware values
			s := make(sessions.ContextValue)
			s[sessions.CtxUser] = session.Username
			s[sessions.CtxCSRF] = session.Values[sessions.CtxCSRF].(string)
			ctx := context.WithValue(r.Context(), sessions.ContextKey(sessions.CtxSession), s)
			// Update metadata for the user
			if err := adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s[sessions.CtxCSRF]); err != nil {
				log.Printf("error updating metadata for user %s: %v", session.Username, err)
			}
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthSAML:
			_, err := samlMiddleware.Session.GetSession(r)
			if err != nil {
				log.Printf("GetSession %v", err)
			}
			cookiev, err := r.Cookie(authCookieName)
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
			authenticated, session := sessionsmgr.CheckAuth(r)
			if !authenticated {
				// Create user if it does not exist
				if !adminUsers.Exists(jwtdata.Username) {
					log.Printf("user not found: %s", jwtdata.Username)
					http.Redirect(w, r, forbiddenPath, http.StatusFound)
					return
				}
				u, err := adminUsers.Get(jwtdata.Username)
				if err != nil {
					log.Printf("error getting user %s: %v", jwtdata.Username, err)
					http.Redirect(w, r, forbiddenPath, http.StatusFound)
					return
				}
				access, err := adminUsers.GetEnvAccess(u.Username, u.DefaultEnv)
				if err != nil {
					log.Printf("error getting access for %s: %v", jwtdata.Username, err)
					http.Redirect(w, r, forbiddenPath, http.StatusFound)
					return
				}
				// Create new session
				session, err = sessionsmgr.Save(r, w, u, access)
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
			ctx := context.WithValue(r.Context(), sessions.ContextKey(sessions.CtxSession), s)
			// Update metadata for the user
			err = adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s[sessions.CtxCSRF])
			if err != nil {
				log.Printf("error updating metadata for user %s: %v", session.Username, err)
			}
			// Access granted
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
