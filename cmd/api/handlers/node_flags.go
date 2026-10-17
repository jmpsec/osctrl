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
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// currentFlagsOverride returns the node's flags override in env, or nil. A row
// left over from another environment is not applied by osctrl-tls, so it is
// treated as absent here too.
func (h *HandlersApi) currentFlagsOverride(env environments.TLSEnvironment, node nodes.OsqueryNode) (*nodeconfig.FlagsOverride, error) {
	o, err := h.FlagsOverrides.Get(node.UUID)
	if err != nil || o == nil || o.EnvironmentID != env.ID {
		return nil, err
	}
	return o, nil
}

// nodeFlagsState builds the response. Applied mirrors what osctrl-tls serves
// osctrld: the environment flags unless an unexpired override merges cleanly.
func (h *HandlersApi) nodeFlagsState(env environments.TLSEnvironment, node nodes.OsqueryNode, o *nodeconfig.FlagsOverride) (types.NodeFlagsResponse, error) {
	envFlags, err := h.Envs.NodeFlags(env, "", "", h.OsqueryValues)
	if err != nil {
		return types.NodeFlagsResponse{}, err
	}
	cfg, err := h.currentOverride(env, node)
	if err != nil {
		return types.NodeFlagsResponse{}, err
	}
	st, err := h.FlagsOverrides.Status(node.UUID)
	if err != nil {
		return types.NodeFlagsResponse{}, err
	}
	resp := types.NodeFlagsResponse{Environment: envFlags, Applied: envFlags}
	if o != nil {
		updatedAt := o.UpdatedAt
		resp.Override = o.Flags
		resp.ExpiresAt = o.ExpiresAt
		resp.Expired = o.Expired(time.Now())
		resp.UpdatedBy = o.UpdatedBy
		resp.UpdatedAt = &updatedAt
		if !resp.Expired {
			if merged, err := nodeconfig.MergeFlags(envFlags, o.Flags); err == nil {
				resp.Applied = merged
			} else {
				log.Err(err).Msgf("node %s: stored flags override does not apply", o.NodeUUID)
			}
		}
	}
	nodeCfg := ""
	if cfg != nil {
		nodeCfg = cfg.Config
	}
	resp.Conflicts = nodeconfig.FlagOptionConflicts(resp.Override, env.Configuration, nodeCfg)
	// A status from another environment describes flags this one never served.
	if st != nil && st.EnvironmentID == env.ID {
		resp.Osctrld = osctrldStatusView(st, o)
	}
	return resp, nil
}

// osctrldStatusView reports the node's osctrld status. RejectedCurrent compares
// the host-reported apply time with the override's last update; it is clamped
// to the server's fetch time so a skewed or forged future time cannot pin a
// rejection. An expired override is no longer served, so it is never current.
// SHA-256s cannot be compared: osctrld hashes the flags with the
// host's real secret and certificate paths.
func osctrldStatusView(st *nodeconfig.OsctrldStatus, o *nodeconfig.FlagsOverride) *types.OsctrldStatusView {
	v := &types.OsctrldStatusView{
		LastFetchedAt: st.LastFetchedAt,
		ApplyResult:   st.ApplyResult,
		ApplyError:    st.ApplyError,
		ApplyAt:       st.ApplyAt,
	}
	if o != nil && !o.Expired(time.Now()) && st.ApplyResult == "rejected" && st.ApplyAt != nil {
		at := *st.ApplyAt
		if st.LastFetchedAt.Before(at) {
			at = st.LastFetchedAt
		}
		v.RejectedCurrent = at.After(o.UpdatedAt)
	}
	return v
}

// serveNodeFlags writes the node's flags state for o.
func (h *HandlersApi) serveNodeFlags(w http.ResponseWriter, env environments.TLSEnvironment, node nodes.OsqueryNode, o *nodeconfig.FlagsOverride) {
	resp, err := h.nodeFlagsState(env, node, o)
	if err != nil {
		apiErrorResponse(w, "error getting node flags", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// NodeFlagsGetHandler - GET Handler for a node's flags override
// @Summary Get node flags override
// @Description Returns the node's osquery flags override, the environment flags, the flags the node's osctrld is served, flags that are also set as configuration options, and the last osctrld fetch. The osctrld apply_result, apply_error and apply_at fields are reported by the host and are untrusted.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeFlagsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/flags [get]
func (h *HandlersApi) NodeFlagsGetHandler(w http.ResponseWriter, r *http.Request) {
	env, node, _, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	o, err := h.currentFlagsOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node flags override", http.StatusInternalServerError, err)
		return
	}
	h.serveNodeFlags(w, env, node, o)
}

// NodeFlagsPutHandler - PUT Handler to set a node's flags override
// @Summary Set node flags override
// @Description Sets the node's osquery flags override, one flag per line, merged over the environment flags osctrld fetches. Flags that control the connection to osctrl and repeated flags are refused. The osctrld apply_result, apply_error and apply_at fields are reported by the host and are untrusted.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param request body types.NodeFlagsRequest true "Request body"
// @Success 200 {object} types.NodeFlagsResponse
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
// @Router /api/v1/nodes/{env}/node/{uuid}/flags [put]
func (h *HandlersApi) NodeFlagsPutHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	var req types.NodeFlagsRequest
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
	if err := nodeconfig.ValidateFlagsOverride(req.Override); err != nil {
		apiErrorResponse(w, "invalid override: "+err.Error(), http.StatusBadRequest, err)
		return
	}
	before, err := h.currentFlagsOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node flags override", http.StatusInternalServerError, err)
		return
	}
	stored, err := h.FlagsOverrides.Set(context.WithoutCancel(r.Context()), nodeconfig.FlagsOverride{
		NodeUUID:      node.UUID,
		EnvironmentID: env.ID,
		Flags:         req.Override,
		ExpiresAt:     req.ExpiresAt,
		UpdatedBy:     user,
	})
	if err != nil {
		apiErrorResponse(w, "error saving node flags override", http.StatusInternalServerError, err)
		return
	}
	expires := "never"
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	h.AuditLog.NodeAction(user, "set flags override on node "+node.UUID+" (expires "+expires+"): before="+overrideFlags(before)+" after="+req.Override, utils.GetIP(r), env.ID)
	h.serveNodeFlags(w, env, node, stored)
}

// NodeFlagsDeleteHandler - DELETE Handler to remove a node's flags override
// @Summary Remove node flags override
// @Description Removes the node's osquery flags override so its osctrld is served the environment flags. The osctrld apply_result, apply_error and apply_at fields are reported by the host and are untrusted.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeFlagsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/flags [delete]
func (h *HandlersApi) NodeFlagsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	before, err := h.currentFlagsOverride(env, node)
	if err != nil {
		apiErrorResponse(w, "error getting node flags override", http.StatusInternalServerError, err)
		return
	}
	if err := h.FlagsOverrides.Delete(context.WithoutCancel(r.Context()), node.UUID); err != nil {
		apiErrorResponse(w, "error removing node flags override", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.NodeAction(user, "removed flags override on node "+node.UUID+": before="+overrideFlags(before), utils.GetIP(r), env.ID)
	h.serveNodeFlags(w, env, node, nil)
}

func overrideFlags(o *nodeconfig.FlagsOverride) string {
	if o == nil {
		return "none"
	}
	return o.Flags
}
