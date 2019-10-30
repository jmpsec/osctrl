package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/settings"
)

// contextValue to hold session data in the context
type contextValue map[string]string

// contextKey to help with the context key, to pass session data
type contextKey string

const (
	// Username to use when there is no authentication
	usernameAPI string = "osctrl-api-user"
	// Key to identify request context
	contextAPI string = "osctrl-api-context"
)

const (
	adminLevel string = "admin"
	userLevel  string = "user"
)

// Helper to verify if user is an admin
func checkAdminLevel(level string) bool {
	return (level == adminLevel)
}

// Helper to extract token from header
func extractHeaderToken(r *http.Request) string {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) != 2 {
		return ""
	}
	return strings.TrimSpace(splitToken[1])
}

// Handler to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch apiConfig.Auth {
		case settings.AuthNone:
			// Set middleware values
			s := make(contextValue)
			s["user"] = usernameAPI
			s["level"] = adminLevel
			ctx := context.WithValue(r.Context(), contextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthJWT:
			token := extractHeaderToken(r)
			if token == "" {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			claims, valid := apiUsers.CheckToken(jwtConfig.JWTSecret, token)
			if !valid {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			// Update metadata for the user
			err := apiUsers.UpdateTokenIPAddress(r.Header.Get("X-Real-IP"), claims.Username)
			if err != nil {
				log.Printf("error updating token for user %s: %v", claims.Username, err)
			}
			// Set middleware values
			s := make(contextValue)
			s["user"] = claims.Username
			s["level"] = claims.Level
			ctx := context.WithValue(r.Context(), contextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
