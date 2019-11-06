package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
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
	if !checkAdminLevel(ctx[ctxLevel]) {
		log.Printf("%s has insuficient permissions", ctx[ctxUser])
		incMetric(metricTokenErr)
		return
	}
	vars := mux.Vars(r)
	// Extract username
	username, ok := vars["username"]
	if !ok {
		log.Println("error getting username")
		incMetric(metricTokenErr)
		return
	}
	returned := TokenJSON{}
	if adminUsers.Exists(username) {
		user, err := adminUsers.Get(username)
		if err != nil {
			log.Println("error getting user")
			incMetric(metricTokenErr)
			return
		}
		// Prepare data to be returned
		returned = TokenJSON{
			Token:     user.APIToken,
			Expires:   user.TokenExpire.String(),
			ExpiresTS: user.TokenExpire.String(),
		}
	}
	// Serialize JSON
	returnedJSON, err := json.Marshal(returned)
	if err != nil {
		log.Printf("error serializing JSON %v", err)
		incMetric(metricTokenErr)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
	incMetric(metricTokenOK)
}

// Handle POST request for /tokens/{username}/refresh
func tokensPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricTokenReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		adminErrorResponse(w, "insuficient permissions", http.StatusForbidden, nil)
		incMetric(metricTokenErr)
		return
	}
	vars := mux.Vars(r)
	// Extract username
	username, ok := vars["username"]
	if !ok {
		incMetric(metricTokenErr)
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	var t TokenRequest
	response := TokenResponse{}
	if err := json.NewDecoder(r.Body).Decode(&t); err == nil {
		// Check CSRF Token
		if checkCSRFToken(ctx[ctxCSRF], t.CSRFToken) {
			if adminUsers.Exists(username) {
				user, err := adminUsers.Get(username)
				if err != nil {
					adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
					return
				}
				if user.Admin {
					token, exp, err := adminUsers.CreateToken(user.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
					if err != nil {
						adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
						return
					}
					if err = adminUsers.UpdateToken(user.Username, token, exp); err != nil {
						adminErrorResponse(w, "error updating token", http.StatusInternalServerError, err)
						return
					}
					response = TokenResponse{
						Token:        token,
						ExpirationTS: exp.String(),
						Expiration:   exp.String(),
					}
				}
			} else {
				adminErrorResponse(w, "user not found", http.StatusNotFound, nil)
				return
			}
		} else {
			adminErrorResponse(w, "invalid CSRF token", http.StatusForbidden, nil)
			return
		}
	} else {
		incMetric(metricTokenErr)
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, nil)
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, response)
	incMetric(metricTokenOK)
}
