package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	if h.Settings.DebugService(config.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned query %s", name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, query)
}

// QueriesRunHandler - POST Handler to run a query
func (h *HandlersApi) QueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	queryName := queries.GenQueryName()
	newQuery := queries.DistributedQuery{
		Query:         q.Query,
		Name:          queryName,
		Creator:       ctx[ctxUser],
		Expected:      0,
		Executions:    0,
		Active:        true,
		Expired:       false,
		Expiration:    expTime,
		Completed:     false,
		Deleted:       false,
		Hidden:        q.Hidden,
		Type:          queries.StandardQueryType,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	// Get the query id
	newQuery, err = h.Queries.Get(queryName, env.ID)
	if err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}

	// List all the nodes that match the query
	var expected []uint

	targetNodesID := []uint{}
	// Current logic is to select nodes meeting all criteria in the query
	// TODO: I believe we should only allow to list nodes in one environment in URL paths
	// We will refactor this part to be tag based queries and add more options to the query
	if len(q.Environments) > 0 {
		expected = []uint{}
		for _, e := range q.Environments {
			if (e != "") && h.Envs.Exists(e) {
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					apiErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.ID)
				}
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Create platform target
	if len(q.Platforms) > 0 {
		expected = []uint{}
		platforms, _ := h.Nodes.GetAllPlatforms()
		for _, p := range q.Platforms {
			if (p != "") && checkValidPlatform(platforms, p) {
				nodes, err := h.Nodes.GetByPlatform(p, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					apiErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.ID)
				}
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Create UUIDs target
	if len(q.UUIDs) > 0 {
		expected = []uint{}
		for _, u := range q.UUIDs {
			if u != "" {
				node, err := h.Nodes.GetByUUID(u)
				if err != nil {
					log.Warn().Msgf("error getting node %s and failed to create node query for it", u)
					continue
				}
				expected = append(expected, node.ID)
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Create hostnames target
	// Currently we are using the GetByIdentifier function and it need be more clear
	// about the definition of the identifier
	if len(q.Hosts) > 0 {
		expected = []uint{}
		for _, hostName := range q.Hosts {
			if hostName != "" {
				node, err := h.Nodes.GetByIdentifier(hostName)
				if err != nil {
					log.Warn().Msgf("error getting node %s and failed to create node query for it", hostName)
					continue
				}
				expected = append(expected, node.ID)
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
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
	if err := h.Queries.SetExpected(queryName, len(targetNodesID), env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiQueriesResponse{Name: newQuery.Name})
}

// QueriesActionHandler - POST Handler to delete/expire a query
func (h *HandlersApi) QueriesActionHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// AllQueriesShowHandler - GET Handler to return all queries in JSON
func (h *HandlersApi) AllQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
}

// QueryListHandler - GET Handler to return queries in JSON by target and environment
func (h *HandlersApi) QueryListHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
}

// QueryResultsHandler - GET Handler to return a single query results in JSON
func (h *HandlersApi) QueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(config.ServiceAPI, settings.NoEnvironmentID), false)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queryLogs)
}
