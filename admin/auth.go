package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
)

const (
	adminLevel string = "admin"
	userLevel  string = "user"
)

const (
	ctxUser  = "user"
	ctxEmail = "email"
	ctxCSRF  = "csrftoken"
	ctxAdmin = "admin"
	ctxLevel = "user"
)

// Helper to verify if user is an admin
func checkAdminLevel(user users.AdminUser) bool {
	return user.Admin
}

// Helper to check if query access is granted
func checkQueryLevel(permissions users.UserPermissions) bool {
	return permissions.Query
}

// Helper to check if carve access is granted
func checkCarveLevel(permissions users.UserPermissions) bool {
	return permissions.Carve
}

// Helper to check if environment access is granted
func checkEnvironmentLevel(permissions users.UserPermissions, environment string) bool {
	return permissions.Environments[environment]
}

// Helper to check permissions for a user
func checkPermissions(username string, query, carve, env bool, environment string) bool {
	exist, user := adminUsers.ExistsGet(username)
	if !exist {
		return false
	}
	// Admin always have access
	if user.Admin {
		return true
	}
	perms, err := adminUsers.ConvertPermissions(user.Permissions.RawMessage)
	if err != nil {
		log.Printf("error converting permissions %v", err)
		return false
	}
	// Check for query access
	if query {
		return checkQueryLevel(perms)
	}
	// Check for carve access
	if carve {
		return checkCarveLevel(perms)
	}
	// Check for environment access
	if env {
		return checkEnvironmentLevel(perms, environment)
	}
	// At this point, no access granted
	return false
}

// Handler to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case settings.AuthDB:
			// Check if user is already authenticated
			authenticated, session := sessionsmgr.CheckAuth(r)
			if !authenticated {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Set middleware values
			s := make(contextValue)
			s["user"] = session.Username
			s["csrftoken"] = session.Values["csrftoken"].(string)
			if session.Values["admin"].(bool) {
				s["level"] = adminLevel
			} else {
				s["level"] = userLevel
			}
			ctx := context.WithValue(r.Context(), contextKey("session"), s)
			// Update metadata for the user
			err := adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s["csrftoken"])
			if err != nil {
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
					// Create new session
					session, err = sessionsmgr.Save(r, w, u)
					if err != nil {
						log.Printf("session error: %v", err)
						http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
						return
					}
				}
				// Set middleware values
				s := make(contextValue)
				s["user"] = session.Username
				s["csrftoken"] = session.Values["csrftoken"].(string)
				if session.Values["admin"].(bool) {
					s["level"] = adminLevel
				} else {
					s["level"] = userLevel
				}
				ctx := context.WithValue(r.Context(), contextKey("session"), s)
				// Update metadata for the user
				err = adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username, s["csrftoken"])
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
			s := make(contextValue)
			s["user"] = username
			s["csrftoken"] = generateCSRF()
			for _, group := range groups {
				if group == headersConfig.AdminGroup {
					s["level"] = adminLevel
					// We can break because there is no greater permission level
					break
				} else if group == headersConfig.UserGroup {
					s["level"] = userLevel
					// We can't break because we might still find a higher permission level
				}
			}
			// This user didn't present a group that has permission to use the service
			if _, ok := s["level"]; !ok {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			newUser, err := adminUsers.New(username, "", email, fullname, (s["level"] == adminLevel))
			if err != nil {
				log.Printf("Error with new user %s: %v", username, err)
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			if err := adminUsers.Create(newUser); err != nil {
				log.Printf("Error creating user %s: %v", username, err)
				http.Redirect(w, r, forbiddenPath, http.StatusFound)
				return
			}
			// _, session := sessionsmgr.CheckAuth(r)
			// s["csrftoken"] = session.Values["csrftoken"].(string)
			ctx := context.WithValue(r.Context(), contextKey("session"), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

// Helper to prepare context based on the user
func prepareContext(user users.AdminUser) contextValue {
	s := make(contextValue)
	s[ctxUser] = user.Username
	s[ctxEmail] = user.Email
	s[ctxCSRF] = user.CSRFToken
	s[ctxAdmin] = strconv.FormatBool(user.Admin)
	return s
}
