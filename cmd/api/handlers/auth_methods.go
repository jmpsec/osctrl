package handlers

import (
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// AuthMethod describes one auth surface advertised to the SPA.
type AuthMethod struct {
	Type string `json:"type"`
	// LoginURL is the relative URL the SPA should redirect to.
	// For federated providers, includes the provider row ID.
	LoginURL string `json:"loginUrl"`
	// Name is the human-facing label for the provider (e.g.
	// "GitHub", "Google", "Corp Keycloak"). Empty for "password".
	Name string `json:"name,omitempty"`
	// ID is the auth_providers row ID, used by the SPA to build
	// the callback URL. 0 for "password".
	ID uint `json:"id,omitempty"`
}

type AuthMethodsResponse struct {
	Methods []AuthMethod `json:"methods"`
}

func (h *HandlersApi) AuthMethodsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	methods := []AuthMethod{
		{Type: "password", LoginURL: "/api/v1/login"},
	}
	// If the new AuthProviderRegistry is wired, read from it.
	// This supports multiple OIDC/SAML providers with a selector.
	if h.AuthProviders != nil {
		for _, p := range h.AuthProviders.AllProviders() {
			methods = append(methods, AuthMethod{
				Type:     p.Type,
				LoginURL: fmt.Sprintf("/api/v1/auth/%s/%d/login", p.Type, p.ID),
				Name:     p.Name,
				ID:       p.ID,
			})
		}
	} else {
		// Fallback to the legacy boolean flags for backwards compat.
		if h.OIDCEnabled {
			methods = append(methods, AuthMethod{
				Type:     "oidc",
				LoginURL: "/api/v1/auth/oidc/login",
			})
		}
		if h.SAMLEnabled {
			methods = append(methods, AuthMethod{
				Type:     "saml",
				LoginURL: "/api/v1/auth/saml/login",
			})
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AuthMethodsResponse{Methods: methods})
}
