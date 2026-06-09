package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// QueryTargets enumerates the target filters accepted by QueryListHandler.
// TargetHiddenActive is intentionally excluded: no UI tab references it and
// GetByEnvTargetPaged has no branch for it (mirrors Gets() which returns nothing).
var QueryTargets = map[string]bool{
	queries.TargetAll:             true,
	queries.TargetAllFull:         true,
	queries.TargetActive:          true,
	queries.TargetCompleted:       true,
	queries.TargetExpired:         true,
	queries.TargetSaved:           true,
	queries.TargetHiddenCompleted: true,
	queries.TargetDeleted:         true,
	queries.TargetHidden:          true,
}

// QueryShowHandler - GET Handler to return a single query in JSON
func (h *HandlersApi) QueryShowHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get query by name
	query, err := h.Queries.Get(name, env.ID)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "query not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting query", http.StatusInternalServerError, err)
		}
		return
	}
	// Targets — the creation-time scope (platform/uuid/hostname/tag rows
	// stored in the query_targets table). The legacy admin shows them
	// in a small Type/Value table on the query detail page; surface
	// them here so the SPA can render the same. Best-effort: a fetch
	// error doesn't fail the request — we still return the query.
	type queryTarget struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	targets := []queryTarget{}
	if rows, terr := h.Queries.GetTargets(name); terr == nil {
		for _, t := range rows {
			targets = append(targets, queryTarget{Type: t.Type, Value: t.Value})
		}
	} else {
		log.Debug().Err(terr).Msgf("query targets fetch failed for %s", name)
	}
	resp := struct {
		queries.DistributedQuery
		Targets []queryTarget `json:"targets"`
	}{
		DistributedQuery: query,
		Targets:          targets,
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned query %s", name)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// QueriesRunHandler - POST Handler to run a query
func (h *HandlersApi) QueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var q types.ApiDistributedQueryRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusBadRequest, nil)
		return
	}
	// Check if query is carve and user has permissions to carve
	if queries.IsCarveQuery(q.Query) {
		if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
			apiErrorResponse(w, fmt.Sprintf("%s has insufficient permissions to carve", ctx[ctxUser]), http.StatusForbidden, nil)
			return
		}
	}
	// Make sure the user has permissions to run queries in the environments
	for _, e := range q.Environments {
		if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, e) {
			apiErrorResponse(w, fmt.Sprintf("%s has insufficient permissions to run queries in environment %s", ctx[ctxUser], e), http.StatusForbidden, nil)
			return
		}
	}
	expTime := queries.QueryExpiration(q.ExpHours)
	if q.ExpHours == 0 {
		expTime = time.Time{}
	}
	// Prepare and create new query
	newQuery := queries.DistributedQuery{
		Query:         q.Query,
		Name:          queries.GenQueryName(),
		Creator:       ctx[ctxUser],
		Active:        true,
		Expiration:    expTime,
		Hidden:        q.Hidden,
		Type:          queries.StandardQueryType,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(&newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	// Prepare data for the handler code
	data := handlers.ProcessingQuery{
		Envs:          q.Environments,
		Platforms:     q.Platforms,
		UUIDs:         q.UUIDs,
		Hosts:         q.Hosts,
		Tags:          q.Tags,
		EnvID:         env.ID,
		InactiveHours: h.Settings.InactiveHours(settings.NoEnvironmentID),
	}
	manager := handlers.Managers{
		Nodes: h.Nodes,
		Envs:  h.Envs,
		Tags:  h.Tags,
	}
	targetNodesID, err := handlers.CreateQueryCarve(data, manager, newQuery)
	if err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	// If the list is empty, we don't need to create node queries
	if len(targetNodesID) != 0 {
		if err := h.Queries.CreateNodeQueries(targetNodesID, newQuery.ID); err != nil {
			log.Err(err).Msgf("error creating node queries for query %s", newQuery.Name)
			apiErrorResponse(w, "error creating node queries", http.StatusInternalServerError, err)
			return
		}
	}
	// Update value for expected
	if err := h.Queries.SetExpected(newQuery.Name, len(targetNodesID), env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		return
	}
	// Return query name as serialized response
	log.Debug().Msgf("Created query %s with id %d", newQuery.Name, newQuery.ID)
	h.AuditLog.NewQuery(ctx[ctxUser], newQuery.Query, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiQueriesResponse{Name: newQuery.Name})
}

// QueriesActionHandler - POST Handler to delete/expire a query
func (h *HandlersApi) QueriesActionHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	var msgReturn string
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	// Query can not be empty
	nameVar := r.PathValue("name")
	if nameVar == "" {
		apiErrorResponse(w, "name can not be empty", http.StatusBadRequest, nil)
		return
	}
	// Check if query exists
	if !h.Queries.Exists(nameVar, env.ID) {
		apiErrorResponse(w, "query not found", http.StatusNotFound, nil)
		return
	}
	switch actionVar {
	case settings.QueryDelete:
		if err := h.Queries.Delete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("query %s deleted successfully", nameVar)
	case settings.QueryExpire:
		if err := h.Queries.Expire(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error expiring query", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("query %s expired successfully", nameVar)
	case settings.QueryComplete:
		if err := h.Queries.Complete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error completing query", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("query %s completed successfully", nameVar)
	}
	// Return message as serialized response
	log.Debug().Msgf("Returned message %s", msgReturn)
	h.AuditLog.QueryAction(ctx[ctxUser], actionVar+" query "+nameVar, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// AllQueriesShowHandler - GET Handler to return all queries in JSON
func (h *HandlersApi) AllQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get queries
	queries, err := h.Queries.GetQueries(queries.TargetCompleted, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		return
	}
	if len(queries) == 0 {
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned %d queries", len(queries))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
}

// QueryListHandler - GET Handler to return queries in JSON by target and environment (paginated)
//
// Query params: page, page_size, q (free-text search), sort (column key), dir (asc|desc)
func (h *HandlersApi) QueryListHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error with target", http.StatusBadRequest, nil)
		return
	}
	// Verify target
	if !QueryTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, nil)
		return
	}
	// Parse pagination / search / sort params
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	search := q.Get("q")
	sortCol := q.Get("sort")
	desc := strings.ToLower(q.Get("dir")) != "asc"

	// Clamp pagination once at the handler so the response echoes effective
	// values; the package function still clamps defensively.
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}

	result, err := h.Queries.GetByEnvTargetPaged(env.ID, targetVar, queries.StandardQueryType, search, page, pageSize, sortCol, desc)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		return
	}

	// Empty result is a valid state — return HTTP 200 with empty items.
	items := result.Items
	if items == nil {
		items = []queries.DistributedQuery{}
	}
	var totalPages int
	if result.TotalItems > 0 {
		totalPages = int((result.TotalItems + int64(pageSize) - 1) / int64(pageSize))
	}

	resp := types.QueriesPagedResponse{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		TotalItems: result.TotalItems,
		TotalPages: totalPages,
	}

	// Serialize and serve JSON
	log.Debug().Msgf("Returned %d queries (page %d of %d)", len(items), page, totalPages)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// QueryResultsHandler - GET Handler to return paginated query results in JSON
//
// Path:   /api/v1/queries/{env}/results/{name}
// Params: page, page_size, since (RFC3339 timestamp; unparseable → ignored)
//
// Empty results are a valid state and return HTTP 200 with items: [].
func (h *HandlersApi) QueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Verify the named query belongs to THIS env. logging.GetQueryResults
	// filters on `name` only — without this gate a user with QueryLevel on
	// env A could pull results from env B by passing B's query name in
	// A's URL.
	if !h.Queries.Exists(name, env.ID) {
		apiErrorResponse(w, "query not found", http.StatusNotFound, nil)
		return
	}

	// Parse pagination + since cursor
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	if page <= 0 {
		page = 1
	}
	var since time.Time
	var sinceEcho string
	if s := strings.TrimSpace(q.Get("since")); s != "" {
		if t, perr := time.Parse(time.RFC3339, s); perr == nil {
			since = t
			sinceEcho = s
		}
	}

	items, total, err := logging.GetQueryResults(h.DB, name, since, page, pageSize)
	if err != nil {
		apiErrorResponse(w, "error getting query results", http.StatusInternalServerError, err)
		return
	}
	if items == nil {
		items = []map[string]any{}
	}
	var totalPages int
	if total > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	resp := types.QueryResultsResponse{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		TotalItems: total,
		TotalPages: totalPages,
		Since:      sinceEcho,
	}
	log.Debug().Msgf("Returned query results for %s (page %d of %d, %d rows)", name, page, totalPages, len(items))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// QueryResultsCSVHandler - GET Handler to stream query results as CSV
//
// Path: /api/v1/queries/{env}/results/csv/{name}
//
// (The `.csv` lives as a literal path segment before `{name}` because Go's
// ServeMux grammar requires wildcards to end at `/` or end-of-pattern, so
// `{name}.csv` is a parse error at registration time.)
func (h *HandlersApi) QueryResultsCSVHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Verify the named query belongs to THIS env. See the matching gate
	// in QueryResultsHandler for the rationale.
	if !h.Queries.Exists(name, env.ID) {
		apiErrorResponse(w, "query not found", http.StatusNotFound, nil)
		return
	}
	// Pass 1 (streaming): walk every row, collect the union of column names.
	// We only retain column names here — never the row data — to keep memory at O(columns).
	colSet := make(map[string]struct{})
	if err := logging.StreamQueryResults(h.DB, name, func(row logging.OsqueryQueryData) error {
		var cols map[string]string
		if err := json.Unmarshal([]byte(row.Data), &cols); err != nil {
			cols = map[string]string{"data": row.Data}
		}
		for k := range cols {
			colSet[k] = struct{}{}
		}
		return nil
	}); err != nil {
		apiErrorResponse(w, "error getting query results", http.StatusInternalServerError, err)
		return
	}
	headers := make([]string, 0, len(colSet)+1)
	headers = append(headers, "uuid")
	sortedCols := make([]string, 0, len(colSet))
	for k := range colSet {
		sortedCols = append(sortedCols, k)
	}
	sort.Strings(sortedCols)
	headers = append(headers, sortedCols...)

	// Set response headers BEFORE writing any body.
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".csv"))

	cw := csv.NewWriter(w)
	flusher, _ := w.(http.Flusher)
	if err := cw.Write(headers); err != nil {
		log.Err(err).Msgf("error writing CSV header for %s", name)
		return
	}
	cw.Flush()
	if flusher != nil {
		flusher.Flush()
	}

	// Pass 2 (streaming): write data rows, flushing after each so bytes reach the client incrementally.
	rowCount := 0
	if err := logging.StreamQueryResults(h.DB, name, func(row logging.OsqueryQueryData) error {
		var cols map[string]string
		if err := json.Unmarshal([]byte(row.Data), &cols); err != nil {
			cols = map[string]string{"data": row.Data}
		}
		record := make([]string, len(headers))
		record[0] = row.UUID
		for i, col := range sortedCols {
			record[i+1] = cols[col]
		}
		if werr := cw.Write(record); werr != nil {
			return werr
		}
		cw.Flush()
		if flusher != nil {
			flusher.Flush()
		}
		rowCount++
		return nil
	}); err != nil {
		// Headers already sent; we can only log and stop.
		log.Err(err).Msgf("error streaming CSV rows for %s", name)
		return
	}
	log.Debug().Msgf("Exported CSV for query %s (%d rows)", name, rowCount)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
}

// OsqueryTablesHandler - GET Handler to return the osquery schema tables
//
// Path: /api/v1/osquery/tables
// The schema is global (not env-scoped). Requires any authenticated user.
// Responses are cache-able for one hour since the schema rarely changes.
func (h *HandlersApi) OsqueryTablesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	w.Header().Set("Cache-Control", "private, max-age=3600")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, h.OsqueryTables)
}
