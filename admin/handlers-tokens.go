package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricTokenReq = "admin-token-req"
	metricTokenErr = "admin-token-err"
	metricTokenOK  = "admin-token-ok"
)

// TokenJSON to be used to populate a JSON token
type TokenJSON struct {
	Token     string `json:"token"`
	Expires   string `json:"expires"`
	ExpiresTS string `json:"expires_ts"`
}

// Handle GET requests for /tokens/{username}
func tokensGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricTokenReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	vars := mux.Vars(r)
	// Extract username
	username, ok := vars["username"]
	if !ok {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	returned := TokenJSON{}
	if adminUsers.Exists(username) {
		user, err := adminUsers.Get(username)
		if err != nil {
			adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
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
	incMetric(metricTokenOK)
}

// Handle POST request for /tokens/{username}/refresh
func tokensPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricTokenReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, false, "") {
		adminErrorResponse(w, "insuficient permissions", http.StatusForbidden, nil)
		incMetric(metricTokenErr)
		return
	}
	vars := mux.Vars(r)
	// Extract username and verify
	username, ok := vars["username"]
	if !ok || !adminUsers.Exists(username) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	var t TokenRequest
	var response TokenResponse
	if err := json.NewDecoder(r.Body).Decode(&t); err == nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	user, err := adminUsers.Get(username)
	if err != nil {
		adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Creating token")
	}
	token, exp, err := adminUsers.CreateToken(user.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
	if err != nil {
		adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Updating token")
	}
	if err := adminUsers.UpdateToken(user.Username, token, exp); err != nil {
		adminErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	response = TokenResponse{
		Token:        token,
		ExpirationTS: utils.TimeTimestamp(exp),
		Expiration:   utils.PastFutureTimes(exp),
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	incMetric(metricTokenOK)
}
