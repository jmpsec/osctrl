package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"osctrl/cmd/admin/sessions"
	"osctrl/internal/settings"
	"osctrl/internal/users"
	"osctrl/internal/utils"

	"github.com/rs/zerolog/log"
)

// TokenJSON to be used to populate a JSON token
type TokenJSON struct {
	Token     string `json:"token"`
	Expires   string `json:"expires"`
	ExpiresTS string `json:"expires_ts"`
}

// TokensGETHandler for GET requests for /tokens/{username}
func (h *HandlersAdmin) TokensGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricTokenReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Extract username
	username := r.PathValue("username")
	if username == "" {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	returned := TokenJSON{}
	if h.Users.Exists(username) {
		user, err := h.Users.Get(username)
		if err != nil {
			adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Prepare data to be returned
		returned = TokenJSON{
			Token:     user.APIToken,
			Expires:   utils.PastFutureTimes(user.TokenExpire),
			ExpiresTS: utils.TimeTimestamp(user.TokenExpire),
		}
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, returned)
	h.Inc(metricTokenOK)
}

// TokensPOSTHandler for POST request for /tokens/{username}/refresh
func (h *HandlersAdmin) TokensPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricTokenReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), true)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, "insuficient permissions", http.StatusForbidden, nil)
		h.Inc(metricTokenErr)
		return
	}
	// Extract username and verify
	username := r.PathValue("username")
	if username == "" || !h.Users.Exists(username) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Decoding POST body")
	}
	var t TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	user, err := h.Users.Get(username)
	if err != nil {
		adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Creating token")
	}
	token, exp, err := h.Users.CreateToken(user.Username, h.AdminConfig.Host, t.ExpHours)
	if err != nil {
		adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Updating token")
	}
	if err := h.Users.UpdateToken(user.Username, token, exp); err != nil {
		adminErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	response := TokenResponse{
		Token:        token,
		ExpirationTS: utils.TimeTimestamp(exp),
		Expiration:   utils.PastFutureTimes(exp),
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricTokenOK)
}
