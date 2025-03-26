package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Extract username
	username := r.PathValue("username")
	if username == "" {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		return
	}
	returned := TokenJSON{}
	if h.Users.Exists(username) {
		user, err := h.Users.Get(username)
		if err != nil {
			adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
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
}

// TokensPOSTHandler for POST request for /tokens/{username}/refresh
func (h *HandlersAdmin) TokensPOSTHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAdmin, settings.NoEnvironmentID), true)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, "insuficient permissions", http.StatusForbidden, nil)
		return
	}
	// Extract username and verify
	username := r.PathValue("username")
	if username == "" || !h.Users.Exists(username) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(config.ServiceAdmin) {
		log.Debug().Msg("DebugService: Decoding POST body")
	}
	var t TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	user, err := h.Users.Get(username)
	if err != nil {
		adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
		return
	}
	if h.Settings.DebugService(config.ServiceAdmin) {
		log.Debug().Msg("DebugService: Creating token")
	}
	token, exp, err := h.Users.CreateToken(user.Username, h.AdminConfig.Host, t.ExpHours)
	if err != nil {
		adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
		return
	}
	if h.Settings.DebugService(config.ServiceAdmin) {
		log.Debug().Msg("DebugService: Updating token")
	}
	if err := h.Users.UpdateToken(user.Username, token, exp); err != nil {
		adminErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
		return
	}
	response := TokenResponse{
		Token:        token,
		ExpirationTS: utils.TimeTimestamp(exp),
		Expiration:   utils.PastFutureTimes(exp),
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}
