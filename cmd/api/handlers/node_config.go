package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// nodeConfigMaxBody caps the PUT body for a node configuration override.
const nodeConfigMaxBody = 256 << 10

// nodeConfigTarget resolves the environment, checks the caller is an admin of
// it and resolves the node within it. It writes the error response itself and
// returns ok=false on any failure.
func (h *HandlersApi) nodeConfigTarget(w http.ResponseWriter, r *http.Request) (env environments.TLSEnvironment, node nodes.OsqueryNode, user string, ok bool) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	nodeVar := r.PathValue("uuid")
	if nodeVar == "" {
		apiErrorResponse(w, "error getting node", http.StatusBadRequest, nil)
		return
	}
	// UUID only: hostnames and local names are agent-reported and could match
	// another node.
	node, err = h.Nodes.GetByUUIDEnv(nodeVar, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	return env, node, ctx[ctxUser], true
}

// currentOverride returns the node's override in env, or nil. A row left over
// from another environment is not applied by osctrl-tls, so it is treated as
// absent here too.
func (h *HandlersApi) currentOverride(env environments.TLSEnvironment, node nodes.OsqueryNode) (*nodeconfig.Override, error) {
	o, err := h.NodeConfig.Get(node.UUID)
	if err != nil || o == nil || o.EnvironmentID != env.ID {
		return nil, err
	}
	return o, nil
}

// nodeConfigState builds the response. Applied mirrors what osctrl-tls serves:
// the environment configuration unless an unexpired override merges cleanly.
func nodeConfigState(env environments.TLSEnvironment, o *nodeconfig.Override) types.NodeConfigResponse {
	resp := types.NodeConfigResponse{Environment: env.Configuration, Applied: env.Configuration}
	if o == nil {
		return resp
	}
	updatedAt := o.UpdatedAt
	resp.Override = o.Config
	resp.ExpiresAt = o.ExpiresAt
	resp.Expired = o.Expired(time.Now())
	resp.UpdatedBy = o.UpdatedBy
	resp.UpdatedAt = &updatedAt
	if resp.Expired {
		return resp
	}
	err := nodeconfig.Validate(o.Config)
	if err == nil {
		var merged string
		if merged, err = nodeconfig.Merge(env.Configuration, o.Config); err == nil {
			resp.Applied = merged
		}
	}
	if err != nil {
		log.Err(err).Msgf("node %s: stored config override does not apply", o.NodeUUID)
	}
	return resp
}

// NodeConfigGetHandler - GET Handler for a node's configuration override
// @Summary Get node configuration override
// @Description Returns the node's osquery configuration override, the environment configuration and the configuration the node is served.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeConfigResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/config [get]
func (h *HandlersApi) NodeConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	env, node, _, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	o, err := h.currentOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node config override", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeConfigState(env, o))
}

// NodeConfigPutHandler - PUT Handler to set a node's configuration override
// @Summary Set node configuration override
// @Description Sets the node's osquery configuration override, deep-merged over the environment configuration. Options that control the connection to osctrl and null values are refused.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param request body types.NodeConfigRequest true "Request body"
// @Success 200 {object} types.NodeConfigResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 413 {object} types.ApiErrorResponse "Request body too large"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/config [put]
func (h *HandlersApi) NodeConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	var req types.NodeConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, nodeConfigMaxBody)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			apiErrorResponse(w, "request body too large", http.StatusRequestEntityTooLarge, err)
		} else {
			apiErrorResponse(w, "error parsing PUT body", http.StatusBadRequest, err)
		}
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		apiErrorResponse(w, "expires_at must be in the future", http.StatusBadRequest, nil)
		return
	}
	if err := nodeconfig.Validate(req.Override); err != nil {
		apiErrorResponse(w, "invalid override: "+err.Error(), http.StatusBadRequest, err)
		return
	}
	if _, err := nodeconfig.Merge(env.Configuration, req.Override); err != nil {
		apiErrorResponse(w, "override cannot be merged: "+err.Error(), http.StatusBadRequest, err)
		return
	}
	before, err := h.currentOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node config override", http.StatusInternalServerError, err)
		return
	}
	stored, err := h.NodeConfig.Set(context.WithoutCancel(r.Context()), nodeconfig.Override{
		NodeUUID:      node.UUID,
		EnvironmentID: env.ID,
		Config:        req.Override,
		ExpiresAt:     req.ExpiresAt,
		UpdatedBy:     user,
	})
	if err != nil {
		apiErrorResponse(w, "error saving node config override", http.StatusInternalServerError, err)
		return
	}
	expires := "never"
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	h.AuditLog.NodeAction(user, "set config override on node "+node.UUID+" (expires "+expires+"): before="+overrideConfig(before)+" after="+req.Override, utils.GetIP(r), env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeConfigState(env, stored))
}

// NodeConfigDeleteHandler - DELETE Handler to remove a node's configuration override
// @Summary Remove node configuration override
// @Description Removes the node's osquery configuration override so it is served the environment configuration.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeConfigResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/config [delete]
func (h *HandlersApi) NodeConfigDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	before, err := h.currentOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node config override", http.StatusInternalServerError, err)
		return
	}
	if err := h.NodeConfig.Delete(context.WithoutCancel(r.Context()), node.UUID); err != nil {
		apiErrorResponse(w, "error removing node config override", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.NodeAction(user, "removed config override on node "+node.UUID+": before="+overrideConfig(before), utils.GetIP(r), env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeConfigState(env, nil))
}

func overrideConfig(o *nodeconfig.Override) string {
	if o == nil {
		return "none"
	}
	return o.Config
}
