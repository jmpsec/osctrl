package main

import (
	"context"
	"log"
	"net/http"

	"github.com/crewjam/saml/samlsp"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
)

const (
	adminLevel string = "admin"
	userLevel  string = "user"
	queryLevel string = "query"
	carveLevel string = "carve"
)

const (
	authCookieName = "osctrl-admin-session"
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
			samlSession, err := samlMiddleware.Session.GetSession(r)
			if err != nil {
				log.Printf("GetSession %v", err)
				return
			}
			if samlSession != nil {
				jwtSessionClaims, ok := samlSession.(samlsp.JWTSessionClaims)
				if !ok {
					log.Printf("JWTSessionClaims %v", err)
					return
				}
				samlUser := jwtSessionClaims.Subject
				if samlUser == "" {
					log.Printf("SAML user is empty")
					return
				}
				// Check if user is already authenticated
				authenticated, session := sessionsmgr.CheckAuth(r)
				if !authenticated {
					// Create user if it does not exist
					if !adminUsers.Exists(samlUser) {
						log.Printf("user not found: %s", samlUser)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					u, err := adminUsers.Get(samlUser)
					if err != nil {
						log.Printf("error getting user %s: %v", samlUser, err)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					access, err := adminUsers.GetEnvAccess(u.Username, u.DefaultEnv)
					if err != nil {
						log.Printf("error getting access for %s: %v", samlUser, err)
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
		}
	})
}
