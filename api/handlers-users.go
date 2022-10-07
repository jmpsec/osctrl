package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPIUsersReq = "users-req"
	metricAPIUsersErr = "users-err"
	metricAPIUsersOK  = "users-ok"
)

// GET Handler for single JSON nodes
func apiUserHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract username
	usernameVar, ok := vars["username"]
	if !ok {
		apiErrorResponse(w, "error with username", http.StatusInternalServerError, nil)
		incMetric(metricAPIUsersErr)
		return
	}
	// Get user
	user, err := apiUsers.Get(usernameVar)
	if err != nil {
		apiErrorResponse(w, "error getting user", http.StatusInternalServerError, nil)
		incMetric(metricAPIUsersErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIUsersErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned user %s", usernameVar)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, user)
	incMetric(metricAPIUsersOK)
}

// GET Handler for multiple JSON nodes
func apiUsersHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIUsersErr)
		return
	}
	// Get users
	users, err := apiUsers.All()
	if err != nil {
		apiErrorResponse(w, "error getting users", http.StatusInternalServerError, err)
		incMetric(metricAPIUsersErr)
		return
	}
	if len(users) == 0 {
		apiErrorResponse(w, "no users", http.StatusNotFound, nil)
		incMetric(metricAPIUsersErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned users")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, users)
	incMetric(metricAPIUsersOK)
}
