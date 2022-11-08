package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPILoginReq = "login-req"
	metricAPILoginErr = "login-err"
	metricAPILoginOK  = "login-ok"
)

// POST Handler for API login request
func apiLoginHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPILoginReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPILoginErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPILoginErr)
		return
	}
	var l types.ApiLoginRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAPILoginErr)
		return
	}
	// Check credentials
	access, user := apiUsers.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		apiErrorResponse(w, "invalid credentials", http.StatusForbidden, err)
		incMetric(metricAPILoginErr)
		return
	}
	// Check if user has access to this environment
	if !apiUsers.CheckPermissions(l.Username, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", l.Username))
		incMetric(metricAPILoginErr)
		return
	}
	// Do we have a token already?
	if user.APIToken == "" {
		token, exp, err := apiUsers.CreateToken(l.Username)
		if err != nil {
			apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
			incMetric(metricAPILoginErr)
			return
		}
		if err = apiUsers.UpdateToken(l.Username, token, exp); err != nil {
			apiErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
			incMetric(metricAPILoginErr)
			return
		}
		user.APIToken = token
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returning token for %s", user.Username)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiLoginResponse{Token: user.APIToken})
	incMetric(metricAPILoginOK)
}
