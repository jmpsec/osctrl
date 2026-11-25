package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

const (
	defaultOrphanGraceSeconds = 3600
	maxOrphanGraceSeconds     = 7 * 24 * 3600
)

// CarveOrphansHandler - GET /api/v1/carves/{env}/orphans
//
// Reports S3 carve objects that no carved_files or carved_blocks row
// references. The scan is read-only and ignores objects newer than the grace
// period so in-flight uploads are not reported.
// @Summary List orphaned carve objects
// @Description Reports S3 carve objects with no matching carve metadata row.
// @Tags carves
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param grace_seconds query int false "Ignore objects newer than this many seconds (default 3600, max 604800)"
// @Success 200 {object} carves.OrphanReport
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/carves/{env}/orphans [get]
func (h *HandlersApi) CarveOrphansHandler(w http.ResponseWriter, r *http.Request) {
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
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	grace := defaultOrphanGraceSeconds
	if raw := r.URL.Query().Get("grace_seconds"); raw != "" {
		value, perr := strconv.Atoi(raw)
		if perr != nil || value < 0 || value > maxOrphanGraceSeconds {
			apiErrorResponse(w, "grace_seconds must be between 0 and 604800", http.StatusBadRequest, perr)
			return
		}
		grace = value
	}
	olderThan := time.Now().Add(-time.Duration(grace) * time.Second)
	report, err := h.Carves.FindOrphans(r.Context(), env.Name, olderThan)
	if err != nil {
		if errors.Is(err, carves.ErrOrphanScanUnsupported) {
			apiErrorResponse(w, err.Error(), http.StatusConflict, err)
			return
		}
		apiErrorResponse(w, "error scanning carve objects", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, report)
}
