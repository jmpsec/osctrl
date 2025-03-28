package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	// Key to identify request context
	contextAPI string = "osctrl-api-context"
)

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
func handlerAuthCheck(h http.Handler, auth, jwtSecret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch auth {
		case config.AuthNone:
			// Set middleware values
			s := make(handlers.ContextValue)
			s["user"] = "admin"
			ctx := context.WithValue(r.Context(), handlers.ContextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case config.AuthJWT:
			// Set middleware values
			token := extractHeaderToken(r)
			if token == "" {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			claims, valid := apiUsers.CheckToken(jwtSecret, token)
			if !valid {
				http.Redirect(w, r, forbiddenPath, http.StatusForbidden)
				return
			}
			// Update metadata for the user
			if err := apiUsers.UpdateTokenIPAddress(utils.GetIP(r), claims.Username); err != nil {
				log.Err(err).Msgf("error updating token for user %s", claims.Username)
			}
			// Set middleware values
			s := make(handlers.ContextValue)
			s["user"] = claims.Username
			ctx := context.WithValue(r.Context(), handlers.ContextKey(contextAPI), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}
