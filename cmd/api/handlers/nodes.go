package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// NodeHandler - GET Handler for single JSON nodes
func (h *HandlersApi) NodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract host identifier for node
	nodeVar := r.PathValue("node")
	if nodeVar == "" {
		apiErrorResponse(w, "error getting node", http.StatusBadRequest, nil)
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
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned node %s", nodeVar)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, node)
}

// ActiveNodesHandler - GET Handler for active JSON nodes
func (h *HandlersApi) ActiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets(nodes.ActiveNodes, 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned nodes")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
}

// InactiveNodesHandler - GET Handler for inactive JSON nodes
func (h *HandlersApi) InactiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets(nodes.InactiveNodes, 24)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned nodes")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
}

// AllNodesHandler - GET Handler for all JSON nodes
func (h *HandlersApi) AllNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get nodes
	nodes, err := h.Nodes.Gets(nodes.AllNodes, 0)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodes) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned nodes")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodes)
}

// DeleteNodeHandler - POST Handler to delete single node
func (h *HandlersApi) DeleteNodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var n types.ApiNodeGenericRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	if err := h.Nodes.ArchiveDeleteByUUID(n.UUID); err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned node %s", n.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "node deleted"})
}
