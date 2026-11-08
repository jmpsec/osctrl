package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// sensitivePathsEnv resolves the {env} path value and applies the read or
// write gate. It writes the error response and returns false when refused.
func (h *HandlersApi) sensitivePathsEnv(w http.ResponseWriter, r *http.Request, write bool) (environments.TLSEnvironment, ContextValue, bool) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	env, err := h.Envs.Get(r.PathValue("env"))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return env, ctx, false
	}
	ok := h.canManageEnv(r, ctx[ctxUser], env.UUID)
	if !write {
		ok = ok || h.Users.HasRoleContext(r.Context(), ctx[ctxUser], users.RoleReadOnly)
	}
	if !ok {
		h.denyEnv(w, r, ctx, env.ID, "env admin required for sensitive paths")
		return env, ctx, false
	}
	return env, ctx, true
}

// SensitivePathsListHandler - GET handler for an environment's sensitive carve paths
// @Summary List sensitive carve paths
// @Description Returns the path prefixes only full carve tier may carve or read in the environment.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} environments.SensitivePath
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/sensitive-paths/{env} [get]
func (h *HandlersApi) SensitivePathsListHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.sensitivePathsEnv(w, r, false)
	if !ok {
		return
	}
	rows, err := h.Envs.SensitivePaths(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting sensitive paths", http.StatusInternalServerError, err)
		return
	}
	if rows == nil {
		rows = []environments.SensitivePath{}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rows)
}

// SensitivePathsAddHandler - POST handler to add a sensitive carve path
// @Summary Add sensitive carve path
// @Description Adds a path prefix and cancels pending carves of it queued by users below full carve tier.
// @Tags environments
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.ApiSensitivePathRequest true "Request body"
// @Success 201 {object} environments.SensitivePath
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/sensitive-paths/{env} [post]
func (h *HandlersApi) SensitivePathsAddHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.sensitivePathsEnv(w, r, true)
	if !ok {
		return
	}
	var req types.ApiSensitivePathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	row, err := h.Envs.AddSensitivePath(env.ID, req.Path, ctx[ctxUser])
	if err != nil {
		if errors.Is(err, environments.ErrPathNotAbsolute) || errors.Is(err, environments.ErrPathRejected) || errors.Is(err, environments.ErrPathTooLong) {
			apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		} else {
			apiErrorResponse(w, "error adding sensitive path", http.StatusInternalServerError, err)
		}
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], "sensitive path add "+row.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	if err := h.cancelSensitiveCarves(r.Context(), env, row.Path); err != nil {
		log.Err(err).Msgf("cancelling pending carves for sensitive path %s", row.Path)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, row)
}

// SensitivePathsDeleteHandler - DELETE handler to remove a sensitive carve path
// @Summary Remove sensitive carve path
// @Description Removes a sensitive path prefix from the environment.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Sensitive path ID"
// @Success 200 {object} types.ApiDataResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/sensitive-paths/{env}/{id} [delete]
func (h *HandlersApi) SensitivePathsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.sensitivePathsEnv(w, r, true)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, strconv.IntSize)
	if err != nil {
		apiErrorResponse(w, "invalid id", http.StatusBadRequest, err)
		return
	}
	pathID := uint(id)
	row, err := h.Envs.SensitivePath(env.ID, pathID)
	if err == nil {
		err = h.Envs.DeleteSensitivePath(env.ID, pathID)
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "sensitive path not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error removing sensitive path", http.StatusInternalServerError, err)
		}
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], "sensitive path remove "+row.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: "sensitive path removed"})
}

// cancelSensitiveCarves hard-deletes pending carve node-queries on env's nodes
// whose path touches prefix and whose creator is below full carve tier in env
// (a missing creator fails closed). Console carves store "console:<user>".
func (h *HandlersApi) cancelSensitiveCarves(ctx context.Context, env environments.TLSEnvironment, prefix string) error {
	var pending []queries.NodeQuery
	err := h.DB.Joins("JOIN osquery_nodes ON osquery_nodes.id = node_queries.node_id").
		Where("osquery_nodes.environment = ? AND node_queries.status = ?", env.Name, queries.DistributedQueryStatusPending).
		Find(&pending).Error
	if err != nil || len(pending) == 0 {
		return err
	}
	qIDs := make([]uint, 0, len(pending))
	for _, p := range pending {
		qIDs = append(qIDs, p.QueryID)
	}
	var dqs []queries.DistributedQuery
	if err := h.DB.Where("id IN ? AND type = ?", qIDs, queries.CarveQueryType).Find(&dqs).Error; err != nil {
		return err
	}
	cancelQ := map[uint]bool{}
	for _, q := range dqs {
		if !environments.PathTouches(q.Path, []string{prefix}) {
			continue
		}
		creator := strings.TrimPrefix(q.Creator, "console:")
		if h.Users.Exists(creator) && h.Users.TierContext(ctx, creator, env.UUID, users.CarveLevel) == users.TierFull {
			continue
		}
		cancelQ[q.ID] = true
	}
	var cancel, affected []uint
	for _, p := range pending {
		if cancelQ[p.QueryID] {
			cancel = append(cancel, p.ID)
			affected = append(affected, p.NodeID)
		}
	}
	if len(cancel) == 0 {
		return nil
	}
	if err := h.Queries.CancelNodeQueries(cancel); err != nil {
		return err
	}
	h.Queries.Cache.InvalidateMany(ctx, affected)
	return nil
}
