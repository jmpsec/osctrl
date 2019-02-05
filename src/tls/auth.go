package main

import (
	"net/http"
)

// Hanlder to check access to a resource based on the authentication enabled
func handlerAuthCheck(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch adminConfig.Auth {
		case noAuthLogin:
			// Access always granted
			h.ServeHTTP(w, r)
		case localAuthLogin:
			// Check if user is authenticated
			session, err := store.Get(r, serviceName)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			// Access granted
			h.ServeHTTP(w, r)
		case samlAuthLogin:
			samlMiddleware.RequireAccount(h).ServeHTTP(w, r)
		}
	})
}
