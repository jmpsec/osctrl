package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

var QueryTargets = map[string]bool{
	queries.TargetAll:             true,
	queries.TargetAllFull:         true,
	queries.TargetActive:          true,
	queries.TargetHiddenActive:    true,
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
	if h.DebugHTTPConfig.Enabled {
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
	env, err := h.Envs.GetByUUID(envVar)
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
	// Serialize and serve JSON
	log.Debug().Msgf("Returned query %s", name)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, query)
}

// QueriesRunHandler - POST Handler to run a query
func (h *HandlersApi) QueriesRunHandler(w http.ResponseWriter, r *http.Request) {
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

// QueryListHandler - GET Handler to return queries in JSON by target and environment
func (h *HandlersApi) QueryListHandler(w http.ResponseWriter, r *http.Request) {
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
	// Get queries
	queries, err := h.Queries.GetQueries(targetVar, env.ID)
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

// QueryResultsHandler - GET Handler to return a single query results in JSON
func (h *HandlersApi) QueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.Enabled {
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
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get query by name
	// TODO this is a temporary solution, we need to refactor this and take into consideration the
	// logger for TLS and whether if the results are stored in the DB or a different DB
	queryLogs, err := postgresQueryLogs(h.DB, name)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "query not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting query", http.StatusInternalServerError, err)
		}
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned query results for %s", name)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queryLogs)
}
