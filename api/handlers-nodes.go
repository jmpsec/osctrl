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
	metricAPINodesReq = "nodes-req"
	metricAPINodesErr = "nodes-err"
	metricAPINodesOK  = "nodes-ok"
)

// GET Handler for single JSON nodes
func apiNodeHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPINodesErr)
		return
	}
	// Extract host identifier for node
	nodeVar, ok := vars["node"]
	if !ok {
		apiErrorResponse(w, "error getting node", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get node by identifier
	// FIXME keep a cache of nodes by node identifier
	node, err := nodesmgr.GetByIdentifier(nodeVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		incMetric(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned node %s", nodeVar)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, node)
	incMetric(metricAPINodesOK)
}

// GET Handler for active JSON nodes
func apiActiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := nodesmgr.Gets("active", 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		incMetric(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	incMetric(metricAPINodesOK)
}

// GET Handler for inactive JSON nodes
func apiInactiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := nodesmgr.Gets("inactive", 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		incMetric(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	incMetric(metricAPINodesOK)
}

// GET Handler for all JSON nodes
func apiAllNodesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := nodesmgr.Gets("all", 0)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		incMetric(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	incMetric(metricAPINodesOK)
}

// POST Handler to delete single node
func apiDeleteNodeHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPINodesErr)
		return
	}
	var n types.ApiNodeGenericRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAPINodesErr)
		return
	}
	if err := nodesmgr.ArchiveDeleteByUUID(n.UUID); err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		incMetric(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned node %s", n.UUID)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "node deleted"})
	incMetric(metricAPINodesOK)
}
