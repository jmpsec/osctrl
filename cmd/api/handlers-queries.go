package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"
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
		apiErrorResponse(w, "error getting name", nil)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name)
	if err != nil {
		incMetric(metricAPIErr)
		if err.Error() == "record not found" {
			log.Printf("query not found: %s", name)
			apiHTTPResponse(w, JSONApplicationUTF8, http.StatusNotFound, ApiErrorResponse{Error: "query not found"})
		} else {
			apiErrorResponse(w, "error getting query", err)
		}
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, query)
	incMetric(metricAPIOK)
}

// POST Handler to run a query
func apiQueriesRunHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	var q DistributedQueryRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error parsing POST body", err)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		apiErrorResponse(w, "query can not be empty", nil)
		return
	}
	// Prepare and create new query
	queryName := "query_" + generateQueryName()
	newQuery := queries.DistributedQuery{
		Query:      q.Query,
		Name:       queryName,
		Creator:    "API",
		Expected:   0,
		Executions: 0,
		Active:     true,
		Completed:  false,
		Deleted:    false,
		Repeat:     0,
		Type:       queries.StandardQueryType,
	}
	if err := queriesmgr.Create(newQuery); err != nil {
		apiErrorResponse(w, "error creating query", err)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(q.Environments) > 0 {
		for _, e := range q.Environments {
			if (e != "") && envs.Exists(e) {
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetEnvironment, e); err != nil {
					apiErrorResponse(w, "error creating query environment target", err)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by environment", err)
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
					apiErrorResponse(w, "error creating query platform target", err)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					apiErrorResponse(w, "error getting nodes by platform", err)
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
					apiErrorResponse(w, "error creating query UUID target", err)
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
					apiErrorResponse(w, "error creating query hostname target", err)
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
		apiErrorResponse(w, "error setting expected", err)
		return
	}
	// Return query name as serialized response
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, ApiQueriesResponse{Name: newQuery.Name})
	incMetric(metricAPIOK)
}

// GET Handler to return multiple queries in JSON
func apiQueriesShowHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAPIReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAPI), false)
	// Get queries
	queries, err := queriesmgr.GetQueries(queries.TargetAllFull)
	if err != nil {
		incMetric(metricAPIErr)
		apiErrorResponse(w, "error getting queries", err)
		return
	}
	if len(queries) == 0 {
		incMetric(metricAPIErr)
		log.Printf("no queries")
		apiHTTPResponse(w, JSONApplicationUTF8, http.StatusNotFound, ApiErrorResponse{Error: "no queries"})
		return
	}
	// Serialize and serve JSON
	apiHTTPResponse(w, JSONApplicationUTF8, http.StatusOK, queries)
	incMetric(metricAPIOK)
}
