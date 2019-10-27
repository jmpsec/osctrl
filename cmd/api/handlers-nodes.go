package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// GET Handler for single JSON nodes
func apiNodeHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting uuid", nil)
		return
	}
	// Get node by UUID
	node, err := nodesmgr.GetByUUID(uuid)
	if err != nil {
		incMetric(metricAPIErr)
		if err.Error() == "record not found" {
			log.Printf("node not found: %s", uuid)
			apiHTTPResponse(w, JSONApplicationUTF8, http.StatusNotFound, ApiErrorResponse{Error: "node not found"})
		} else {
			apiErrorResponse(w, "error getting node", err)
		}
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, node)
	incMetric(metricAPIOK)
}

// GET Handler for multiple JSON nodes
func apiNodesHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get nodes
	nodes, err := nodesmgr.Gets("all", 0)
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting nodes", err)
		return
	}
	if len(nodes) == 0 {
		incMetric(metricAPIErr)
		log.Printf("no nodes")
		apiHTTPResponse(w, JSONApplicationUTF8, http.StatusNotFound, ApiErrorResponse{Error: "no nodes"})
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, nodes)
	incMetric(metricAPIOK)
}
