package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// NodeHandler - GET Handler for single JSON nodes
func (h *HandlersApi) NodeHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPINodesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPINodesErr)
		return
	}
	// Extract host identifier for node
	nodeVar := r.PathValue("node")
	if nodeVar == "" {
		apiErrorResponse(w, "error getting node", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get node by identifier
	// FIXME keep a cache of nodes by node identifier
	node, err := h.Nodes.GetByIdentifier(nodeVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned node %s", nodeVar)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, node)
	h.Inc(metricAPINodesOK)
}

// ActiveNodesHandler - GET Handler for active JSON nodes
func (h *HandlersApi) ActiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPINodesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets("active", 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		h.Inc(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	h.Inc(metricAPINodesOK)
}

// InactiveNodesHandler - GET Handler for inactive JSON nodes
func (h *HandlersApi) InactiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPINodesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets("inactive", 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		h.Inc(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	h.Inc(metricAPINodesOK)
}

// AllNodesHandler - GET Handler for all JSON nodes
func (h *HandlersApi) AllNodesHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPINodesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPINodesErr)
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets("all", 0)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		h.Inc(metricAPINodesErr)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Returned nodes")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
	h.Inc(metricAPINodesOK)
}

// DeleteNodeHandler - POST Handler to delete single node
func (h *HandlersApi) DeleteNodeHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPINodesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPINodesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPINodesErr)
		return
	}
	var n types.ApiNodeGenericRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPINodesErr)
		return
	}
	if err := h.Nodes.ArchiveDeleteByUUID(n.UUID); err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		h.Inc(metricAPINodesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned node %s", n.UUID)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "node deleted"})
	h.Inc(metricAPINodesOK)
}
