package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
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
		incMetric(metricAPIEnvsErr)
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
		incMetric(metricAPIEnvsErr)
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
		incMetric(metricAPIEnvsErr)
		return
	}
	var q DistributedQueryRequest
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
	queryName := generateQueryName()
	newQuery := queries.DistributedQuery{
		Query:         q.Query,
		Name:          queryName,
		Creator:       ctx[ctxUser],
		Expected:      0,
		Executions:    0,
		Active:        true,
		Completed:     false,
		Deleted:       false,
		Hidden:        true,
		Type:          queries.StandardQueryType,
		EnvironmentID: env.ID,
	}
	if err := queriesmgr.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(q.Environments) > 0 {
		for _, e := range q.Environments {
			if (e != "") && envs.Exists(e) {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetEnvironment, e); err != nil {
					apiErrorResponse(w, "error creating query environment target", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
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
		for _, p := range q.Platforms {
			if (p != "") && checkValidPlatform(p) {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetPlatform, p); err != nil {
					apiErrorResponse(w, "error creating query platform target", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
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
			if (u != "") && nodesmgr.CheckByUUID(u) {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, u); err != nil {
					apiErrorResponse(w, "error creating query UUID target", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
					return
				}
				expected = append(expected, u)
			}
		}
	}
	// Create hostnames target
	if len(q.Hosts) > 0 {
		for _, h := range q.Hosts {
			if (h != "") && nodesmgr.CheckByHost(h) {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetLocalname, h); err != nil {
					apiErrorResponse(w, "error creating query hostname target", http.StatusInternalServerError, err)
					incMetric(metricAPIQueriesErr)
					return
				}
				expected = append(expected, h)
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := queriesmgr.SetExpected(queryName, len(expectedClear), env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		incMetric(metricAPIQueriesErr)
		return
	}
	// Return query name as serialized response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, ApiQueriesResponse{Name: newQuery.Name})
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
		incMetric(metricAPIEnvsErr)
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
		incMetric(metricAPIEnvsErr)
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
		incMetric(metricAPIEnvsErr)
		return
	}
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, queryLogs)
	incMetric(metricAPIQueriesOK)
}
