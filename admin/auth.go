package main

import (
	"context"
	"net/http"

	"github.com/crewjam/saml/samlsp"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/rs/zerolog/log"
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
				log.Err(err).Msgf("error updating metadata for user %s", session.Username)
			}
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthSAML:
			samlSession, err := samlMiddleware.Session.GetSession(r)
			if err != nil {
				http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
				return
			}
			if samlSession == nil {
				http.Redirect(w, r, samlConfig.LogoutURL, http.StatusFound)
				return
			}
			jwtSessionClaims, ok := samlSession.(samlsp.JWTSessionClaims)
			if !ok {
				return
			}
			samlUser := jwtSessionClaims.Subject
			if samlUser == "" {
				return
			}
			// Check if user is already authenticated
			authenticated, session := sessionsmgr.CheckAuth(r)
			if !authenticated {
				// Create user if it does not exist
				var u users.AdminUser
				if !adminUsers.Exists(samlUser) {
					if !samlConfig.JITProvision {
						log.Error().Msgf("user not found: %s", samlUser)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					u, err = adminUsers.New(samlUser, "", samlUser, "", false)
					if err != nil {
						log.Err(err).Msgf("error creating user %s", samlUser)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
					if err := adminUsers.Create(u); err != nil {
						log.Err(err).Msgf("error creating user %s", samlUser)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
				} else {
					u, err = adminUsers.Get(samlUser)
					if err != nil {
						log.Err(err).Msgf("error getting user %s", samlUser)
						http.Redirect(w, r, forbiddenPath, http.StatusFound)
						return
					}
				}
				// Create new session
				session, err = sessionsmgr.Save(r, w, u)
				if err != nil {
					log.Err(err).Msgf("session error")
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
				log.Err(err).Msgf("error updating metadata for user %s", session.Username)
			}
			// Access granted
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
