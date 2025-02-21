package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// LoginHandler - POST Handler for API login request
func (h *HandlersApi) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPILoginReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPILoginErr)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPILoginErr)
		return
	}
	var l types.ApiLoginRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPILoginErr)
		return
	}
	// Check credentials
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, err)
		h.Inc(metricAPILoginErr)
		return
	}
	// Check if user has access to this environment
	if !h.Users.CheckPermissions(l.Username, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use %s by user %s", h.ServiceName, l.Username))
		h.Inc(metricAPILoginErr)
		return
	}
	// Do we have a token already?
	if user.APIToken == "" {
		token, exp, err := h.Users.CreateToken(l.Username, h.ServiceName, l.ExpHours)
		if err != nil {
			apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
			h.Inc(metricAPILoginErr)
			return
		}
		if err = h.Users.UpdateToken(l.Username, token, exp); err != nil {
			apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
			h.Inc(metricAPILoginErr)
			return
		}
		user.APIToken = token
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returning token for %s", user.Username)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiLoginResponse{Token: user.APIToken})
	h.Inc(metricAPILoginOK)
}
