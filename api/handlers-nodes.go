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
	metricAPINodesReq = "nodes-req"
	metricAPINodesErr = "nodes-err"
	metricAPINodesOK  = "nodes-ok"
)

// GET Handler for single JSON nodes
func apiNodeHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		apiErrorResponse(w, "error getting uuid", http.StatusInternalServerError, nil)
		incMetric(metricAPINodesErr)
		return
	}
	// Get node by UUID
	// FIXME keep a cache of nodes by UUID
	node, err := nodesmgr.GetByUUID(uuid)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		incMetric(metricAPIEnvsErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.EnvLevel, node.Environment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned node %s", uuid)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, node)
	incMetric(metricAPINodesOK)
}

// GET Handler for multiple JSON nodes
func apiNodesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPINodesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIEnvsErr)
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
