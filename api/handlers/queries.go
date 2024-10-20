package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// QueryShowHandler - GET Handler to return a single query in JSON
func (h *HandlersApi) QueryShowHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
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
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(settings.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned query %s", name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, query)
	h.Inc(metricAPIQueriesOK)
}

// QueriesRunHandler - POST Handler to run a query
func (h *HandlersApi) QueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
		return
	}
	var q types.ApiDistributedQueryRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
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
		h.Inc(metricAPIQueriesErr)
		return
	}

	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create targets
	if len(q.Environments) > 0 {
		for _, e := range q.Environments {
			if (e != "") && h.Envs.Exists(e) {
				if err := h.Queries.CreateTarget(newQuery.Name, queries.QueryTargetEnvironment, e); err != nil {
					apiErrorResponse(w, "error creating query environment target", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					apiErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.UUID)
				}
			}
		}
	}
	// Create platform target
	if len(q.Platforms) > 0 {
		platforms, _ := h.Nodes.GetAllPlatforms()
		for _, p := range q.Platforms {
			if (p != "") && checkValidPlatform(platforms, p) {
				if err := h.Queries.CreateTarget(newQuery.Name, queries.QueryTargetPlatform, p); err != nil {
					apiErrorResponse(w, "error creating query platform target", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				nodes, err := h.Nodes.GetByPlatform(p, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					apiErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.UUID)
				}
			}
		}
	}
	// Create UUIDs target
	if len(q.UUIDs) > 0 {
		for _, u := range q.UUIDs {
			if (u != "") && h.Nodes.CheckByUUID(u) {
				if err := h.Queries.CreateTarget(newQuery.Name, queries.QueryTargetUUID, u); err != nil {
					apiErrorResponse(w, "error creating query UUID target", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				expected = append(expected, u)
			}
		}
	}
	// Create hostnames target
	if len(q.Hosts) > 0 {
		for _, _h := range q.Hosts {
			if (_h != "") && h.Nodes.CheckByHost(_h) {
				if err := h.Queries.CreateTarget(newQuery.Name, queries.QueryTargetLocalname, _h); err != nil {
					apiErrorResponse(w, "error creating query hostname target", http.StatusInternalServerError, err)
					h.Inc(metricAPIQueriesErr)
					return
				}
				expected = append(expected, _h)
			}
		}
	}

	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := h.Queries.SetExpected(queryName, len(expectedClear), env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		h.Inc(metricAPICarvesErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiQueriesResponse{Name: newQuery.Name})
	h.Inc(metricAPIQueriesOK)
}

// AllQueriesShowHandler - GET Handler to return all queries in JSON
func (h *HandlersApi) AllQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get queries
	queries, err := h.Queries.GetQueries(queries.TargetCompleted, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		h.Inc(metricAPIQueriesErr)
		return
	}
	if len(queries) == 0 {
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
	h.Inc(metricAPIQueriesOK)
}

// HiddenQueriesShowHandler - GET Handler to return hidden queries in JSON
func (h *HandlersApi) HiddenQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get queries
	queries, err := h.Queries.GetQueries(queries.TargetHiddenCompleted, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		h.Inc(metricAPIQueriesErr)
		return
	}
	if len(queries) == 0 {
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
	h.Inc(metricAPIQueriesOK)
}

// QueryResultsHandler - GET Handler to return a single query results in JSON
func (h *HandlersApi) QueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID), false)
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		h.Inc(metricAPIQueriesErr)
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
		h.Inc(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queryLogs)
	h.Inc(metricAPIQueriesOK)
}
