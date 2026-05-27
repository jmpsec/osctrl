package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// AuditLogsHandler - GET /api/v1/audit-logs
//
// Query params:
//
//	?service=...       exact match on service name
//	?username=...      case-insensitive partial match on username
//	?type=...          log type integer (1..10), see pkg/auditlog.LogType*
//	?env_uuid=...      filter to one environment (resolved to internal ID)
//	?since=RFC3339     created_at >= since
//	?until=RFC3339     created_at <= until
//	?page=N            1-indexed page; default 1
//	?page_size=N       default 50, max 500
//
// Returns the SPA-canonical paginated envelope. The handler audit-logs the
// visit on success.
// @Summary List audit logs
// @Description Returns paginated API audit log entries.
// @Tags audit
// @Produce json
// @Param page query int false "Page number"
// @Param page_size query int false "Page size"
// @Param q query string false "Search query"
// @Param service query string false "Service filter"
// @Param username query string false "Username filter"
// @Param env query string false "Environment filter"
// @Success 200 {object} types.AuditLogsPagedResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/audit-logs [get]
func (h *HandlersApi) AuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	requester := ctx[ctxUser]
	// Super-admins see all operator activity. Non-admins see only
	// their OWN activity — the username filter is force-clamped to
	// the requester regardless of what the client sends. Without
	// this clamp, a non-admin could iterate usernames manually and
	// effectively page through other operators' activity. Defense-
	// in-depth at the handler layer; the SPA also hides the
	// username filter input for non-admins, but the server is the
	// authoritative gate.
	isSuperAdmin := h.Users.IsAdmin(requester)

	q := r.URL.Query()
	filter := auditlog.PageFilter{
		Service:  strings.TrimSpace(q.Get("service")),
		Username: strings.TrimSpace(q.Get("username")),
	}
	if !isSuperAdmin {
		filter.Username = requester
	}
	if v := q.Get("type"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			apiErrorResponse(w, "type must be an integer", http.StatusBadRequest, err)
			return
		}
		if _, ok := auditlog.LogTypes[uint(n)]; !ok {
			apiErrorResponse(w, "type is not a known log_type", http.StatusBadRequest, nil)
			return
		}
		filter.LogType = uint(n)
	}
	if v := q.Get("env_uuid"); v != "" {
		env, err := h.Envs.GetByUUID(v)
		if err != nil {
			apiErrorResponse(w, "env_uuid not found", http.StatusBadRequest, err)
			return
		}
		filter.EnvID = env.ID
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			apiErrorResponse(w, "since must be RFC3339", http.StatusBadRequest, err)
			return
		}
		filter.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			apiErrorResponse(w, "until must be RFC3339", http.StatusBadRequest, err)
			return
		}
		filter.Until = t
	}
	if v := q.Get("page"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			apiErrorResponse(w, "page must be a positive integer", http.StatusBadRequest, err)
			return
		}
		filter.Page = n
	} else {
		filter.Page = 1
	}
	if v := q.Get("page_size"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			apiErrorResponse(w, "page_size must be a positive integer", http.StatusBadRequest, err)
			return
		}
		filter.PageSize = n
	}
	if filter.PageSize == 0 {
		filter.PageSize = 50
	}
	// Mirror the package-layer clamp at the handler so the response
	// envelope echoes the actual effective value and the doc-comment
	// "max 500" remains honest if the package layer's bound ever
	// shifts.
	if filter.PageSize > 500 {
		filter.PageSize = 500
	}

	rows, total, err := h.AuditLog.GetPaged(filter)
	if err != nil {
		apiErrorResponse(w, "error getting audit logs", http.StatusInternalServerError, err)
		return
	}

	// Resolve EnvironmentID → UUID with a single map lookup so the SPA can
	// render env names directly. Empty UUID == no env / system action.
	envMap, _ := h.Envs.GetMapByID()

	items := make([]types.AuditLogView, 0, len(rows))
	for _, r := range rows {
		view := types.AuditLogView{
			ID:            r.ID,
			CreatedAt:     r.CreatedAt,
			Service:       r.Service,
			Username:      r.Username,
			Line:          r.Line,
			LogType:       r.LogType,
			Severity:      r.Severity,
			SourceIP:      r.SourceIP,
			EnvironmentID: r.EnvironmentID,
		}
		if r.EnvironmentID > 0 {
			if e, ok := envMap[r.EnvironmentID]; ok {
				view.EnvUUID = e.UUID
			}
		}
		items = append(items, view)
	}

	totalPages := 0
	if total > 0 {
		totalPages = int((total + int64(filter.PageSize) - 1) / int64(filter.PageSize))
	}
	resp := types.AuditLogsPagedResponse{
		Items:      items,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
		TotalItems: total,
		TotalPages: totalPages,
	}

	// We do NOT audit-log the audit-log view itself. Logging GETs to
	// /audit-logs makes the table self-pollute: every SPA AuditPage
	// open writes its own visit row, every refetch writes another,
	// and the audit table fills with low-signal "alice viewed her
	// own activity" entries that drown out the state-changing events
	// the table actually exists to record. Other GET handlers in
	// this codebase do log visits for SoC traceability, but for the
	// audit endpoint specifically the cost-benefit flips.
	log.Debug().Msgf("Returned %d audit log entries (page=%d, size=%d, total=%d)", len(items), filter.Page, filter.PageSize, total)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}
