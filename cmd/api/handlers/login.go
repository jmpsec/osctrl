package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// LoginHandler - POST Handler for API login request
func (h *HandlersApi) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled, never log the body for login
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	var l types.ApiLoginRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check credentials
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, err)
		return
	}
	// Check if user has access to this environment
	if !h.Users.CheckPermissions(l.Username, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use %s by user %s", h.ServiceName, l.Username))
		return
	}
	// Do we have a token already?
	if user.APIToken == "" {
		token, exp, err := h.Users.CreateToken(l.Username, h.ServiceName, l.ExpHours)
		if err != nil {
			apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
			return
		}
		if err = h.Users.UpdateToken(l.Username, token, exp); err != nil {
			apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
			return
		}
		user.APIToken = token
	}
	h.AuditLog.NewLogin(l.Username, r.RemoteAddr)
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiLoginResponse{Token: user.APIToken})
}
