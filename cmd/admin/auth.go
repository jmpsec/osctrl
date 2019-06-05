package main

import (
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
		case settings.AuthJSON:
			// Check if user is already authenticated
			session, err := store.Get(r, projectName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Update session for the user
			//adminUsers.
			// Access granted
			h.ServeHTTP(w, r)
		case settings.AuthDB:
			// Check if user is already authenticated
			session, err := store.Get(r, projectName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Update session for the user
			//adminUsers.
			// Access granted
			h.ServeHTTP(w, r)
		case settings.AuthSAML:
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r)
		case settings.AuthHeaders:
			// Access always granted
			h.ServeHTTP(w, r)
		}
	})
}

// Helper to return the list of users
