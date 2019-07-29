package main

import (
	"context"
	"log"
	"net/http"

	"github.com/javuto/osctrl/pkg/settings"
)

// Hanlder to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case settings.AuthNone:
			// Access always granted
			h.ServeHTTP(w, r)
		case settings.AuthDB:
			// Check if user is already authenticated
			authenticated, session := sessionsmgr.CheckAuth(r)
			if !authenticated {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Update metadata for the user
			err := adminUsers.UpdateMetadata(session.IPAddress, session.UserAgent, session.Username)
			if err != nil {
				log.Printf("error updating metadata for user %s: %v", session.Username, err)
			}
			// Set middleware values
			s := make(contextValue)
			s["user"] = session.Username
			s["csrftoken"] = session.Values["csrftoken"].(string)
			ctx := context.WithValue(r.Context(), contextKey("session"), s)
			// Access granted
			h.ServeHTTP(w, r.WithContext(ctx))
		case settings.AuthSAML:
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r)
		case settings.AuthHeaders:
			// Access always granted
			h.ServeHTTP(w, r)
		}
	})
}
