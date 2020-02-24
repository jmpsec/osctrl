package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/utils"
	"github.com/jmpsec/osctrl/settings"
)

// GET Handler to return a single query in JSON
func apiQueryShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name)
	if err != nil {
		incMetric(metricAPIErr)
		if err.Error() == "record not found" {
			log.Printf("query not found: %s", name)
			apiErrorResponse(w, "query not found", http.StatusNotFound, nil)
		} else {
			apiErrorResponse(w, "error getting query", http.StatusInternalServerError, err)
		}
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, query)
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Printf("DebugService: Returned query %s", name)
	}
	incMetric(metricAPIOK)
}

// POST Handler to run a query
func apiQueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	var q DistributedQueryRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusInternalServerError, nil)
		return
	}
	// Prepare and create new query
	queryName := generateQueryName()
	newQuery := queries.DistributedQuery{
		Query:      q.Query,
		Name:       queryName,
		Creator:    ctx["user"],
		Expected:   0,
		Executions: 0,
		Active:     true,
		Completed:  false,
		Deleted:    false,
		Hidden:     true,
		Type:       queries.StandardQueryType,
	}
	if err := queriesmgr.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
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
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
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
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
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
					return
				}
				expected = append(expected, h)
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := queriesmgr.SetExpected(queryName, len(expectedClear)); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		return
	}
	// Return query name as serialized response
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, ApiQueriesResponse{Name: newQuery.Name})
	incMetric(metricAPIOK)
}

// GET Handler to return all queries in JSON
func apiAllQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get queries
	queries, err := queriesmgr.GetQueries(queries.TargetCompleted)
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		return
	}
	if len(queries) == 0 {
		incMetric(metricAPIErr)
		log.Printf("no queries")
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, queries)
	incMetric(metricAPIOK)
}

// GET Handler to return hidden queries in JSON
func apiHiddenQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get queries
	queries, err := queriesmgr.GetQueries(queries.TargetHiddenCompleted)
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting queries", http.StatusInternalServerError, err)
		return
	}
	if len(queries) == 0 {
		incMetric(metricAPIErr)
		log.Printf("no queries")
		apiErrorResponse(w, "no queries", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, queries)
	incMetric(metricAPIOK)
}

// GET Handler to return a single query results in JSON
func apiQueryResultsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting name", http.StatusInternalServerError, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(contextKey(contextAPI)).(contextValue)
	if !apiUsers.IsAdmin(ctx["user"]) {
		log.Printf("attempt to use API by user %s", ctx["user"])
		apiErrorResponse(w, "no access", http.StatusForbidden, nil)
		return
	}
	// Get query by name
	queryLogs, err := postgresQueryLogs(name)
	if err != nil {
		incMetric(metricAPIErr)
		if err.Error() == "record not found" {
			log.Printf("query not found: %s", name)
			apiErrorResponse(w, "query not found", http.StatusNotFound, nil)
		} else {
			apiErrorResponse(w, "error getting results", http.StatusInternalServerError, err)
		}
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, queryLogs)
	incMetric(metricAPIOK)
}
