package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricAPIQueriesReq = "queries-req"
	metricAPIQueriesErr = "queries-err"
	metricAPIQueriesOK  = "queries-ok"
)

// GET Handler to return a single query in JSON
func apiQueryShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name, env.ID)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "query not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting query", http.StatusInternalServerError, err)
		}
		incMetric(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned query %s", name)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, query)
	incMetric(metricAPIQueriesOK)
}

// POST Handler to run a query
func apiQueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIQueriesErr)
		return
	}
	var q types.ApiDistributedQueryRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
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
		Completed:     false,
		Deleted:       false,
		Hidden:        q.Hidden,
		Type:          queries.StandardQueryType,
		EnvironmentID: env.ID,
	}
	if err := queriesmgr.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Create UUID target
	if (q.UUID != "") && nodesmgr.CheckByUUID(q.UUID) {
		if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, q.UUID); err != nil {
			apiErrorResponse(w, "error creating query UUID target", http.StatusInternalServerError, err)
			incMetric(metricAPICarvesErr)
			return
		}
	}
	// Update value for expected
	if err := queriesmgr.SetExpected(queryName, 1, env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		incMetric(metricAPICarvesErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiQueriesResponse{Name: newQuery.Name})
	incMetric(metricAPIQueriesOK)
}

// GET Handler to return all queries in JSON
func apiAllQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get queries
	queries, err := queriesmgr.GetQueries(queries.TargetCompleted, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	if len(queries) == 0 {
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
	incMetric(metricAPIQueriesOK)
}

// GET Handler to return hidden queries in JSON
func apiHiddenQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get queries
	queries, err := queriesmgr.GetQueries(queries.TargetHiddenCompleted, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	if len(queries) == 0 {
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queries)
	incMetric(metricAPIQueriesOK)
}

// GET Handler to return a single query results in JSON
func apiQueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIQueriesReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		apiErrorResponse(w, "error with environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get environment
	env, err := envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		incMetric(metricAPIQueriesErr)
		return
	}
	// Get query by name
	// TODO retrieve from redis
	queryLogs, err := postgresQueryLogs(name)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "query not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting query", http.StatusInternalServerError, err)
		}
		incMetric(metricAPIQueriesErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queryLogs)
	incMetric(metricAPIQueriesOK)
}
