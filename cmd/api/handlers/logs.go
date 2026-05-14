package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// NodeLogsResponse is the SPA-canonical response for GET /api/v1/logs/{type}/{env}/{uuid}.
type NodeLogsResponse struct {
	Items []map[string]any `json:"items"`
	Type  string           `json:"type"`
	UUID  string           `json:"uuid"`
	Env   string           `json:"env"`
	Since string           `json:"since,omitempty"`
	Limit int              `json:"limit"`
}

// NodeLogsHandler returns recent log entries for a node.
//
// Path: /api/v1/logs/{type}/{env}/{uuid}
//
//	type:  "status" | "result"
//	env:   UUID or name
//	uuid:  node UUID
//
// Query params:
//
//	since:  RFC3339 timestamp; entries strictly after this point only
//	limit:  1..1000 (default 100)
func (h *HandlersApi) NodeLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	logType := r.PathValue("type")
	switch logType {
	case types.StatusLog, types.ResultLog:
	default:
		apiErrorResponse(w, "invalid log type (status|result)", http.StatusBadRequest, nil)
		return
	}
	envVar := r.PathValue("env")
	nodeUUID := r.PathValue("uuid")

	env, err := h.Envs.Get(envVar)
	if err != nil {
		envByName, err2 := h.Envs.GetByName(envVar)
		if err2 != nil {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		env = envByName
	}

	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}

	// Verify the node exists in this env — prevents probing for arbitrary UUIDs
	// across tenants (resolves cross-tenant log read vector).
	node, err := h.Nodes.GetByUUID(nodeUUID)
	if err != nil {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if node.Environment == "" || !strings.EqualFold(node.Environment, env.Name) {
		apiErrorResponse(w, "node not in environment", http.StatusForbidden, nil)
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	var since time.Time
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			apiErrorResponse(w, "invalid since (expected RFC3339)", http.StatusBadRequest, err)
			return
		}
		since = t
	}
	// Optional free-text filter. Substring match against the log row's
	// human-readable columns (line / message / filename for status logs;
	// name / action / columns JSON for result logs). Server-side so
	// operators can search the full history, not just the visible page.
	search := strings.TrimSpace(q.Get("q"))

	// Use the node's canonical UUID (already upper-cased in the DB) from the
	// verified node record, not the raw URL parameter.
	items, err := logging.GetNodeLogs(h.DB, logType, env.Name, node.UUID, since, limit, search)
	if err != nil {
		apiErrorResponse(w, "failed to query logs", http.StatusInternalServerError, err)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}

	log.Debug().Msgf("Returned %d %s log entries for node %s", len(items), logType, node.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, NodeLogsResponse{
		Items: items,
		Type:  logType,
		UUID:  node.UUID,
		Env:   env.UUID,
		Since: q.Get("since"),
		Limit: limit,
	})
}
