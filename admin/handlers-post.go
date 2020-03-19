package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"

	"github.com/gorilla/mux"
)

const (
	metricAdminReq = "admin-req"
	metricAdminErr = "admin-err"
	metricAdminOK  = "admin-ok"
)

// Handler for login page for POST requests
func loginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	var l LoginRequest
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check credentials
	access, user := adminUsers.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		adminErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	_, err := sessionsmgr.Save(r, w, user)
	if err != nil {
		adminErrorResponse(w, "session error", http.StatusForbidden, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login response sent")
	}
	adminOKResponse(w, "OK")
	incMetric(metricAdminOK)
}

// Handle POST requests to logout
func logoutPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	var l LogoutRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], l.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// Destroy existing session
	if err := sessionsmgr.Destroy(r); err != nil {
		adminErrorResponse(w, "error destroying session", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Logout response sent")
	}
	adminOKResponse(w, "OK")
	incMetric(metricAdminOK)
}

// Handler for POST requests to run queries
func queryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedQueryRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions for query
	if !checkPermissions(ctx[ctxUser], true, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		adminErrorResponse(w, "query can not be empty", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// FIXME check if query is carve and user has permissions to carve
	// Prepare and create new query
	newQuery := newQueryReady(ctx[ctxUser], q.Query)
	if err := queriesmgr.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(q.Environments) > 0 {
		for _, e := range q.Environments {
			if (e != "") && envs.Exists(e) {
				if err := queriesmgr.CreateTarget(newQuery.Name, queries.QueryTargetEnvironment, e); err != nil {
					adminErrorResponse(w, "error creating query environment target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
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
				if err := queriesmgr.CreateTarget(newQuery.Name, queries.QueryTargetPlatform, p); err != nil {
					adminErrorResponse(w, "error creating query platform target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
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
				if err := queriesmgr.CreateTarget(newQuery.Name, queries.QueryTargetUUID, u); err != nil {
					adminErrorResponse(w, "error creating query UUID target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
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
				if err := queriesmgr.CreateTarget(newQuery.Name, queries.QueryTargetLocalname, h); err != nil {
					adminErrorResponse(w, "error creating query hostname target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				expected = append(expected, h)
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := queriesmgr.SetExpected(newQuery.Name, len(expectedClear)); err != nil {
		adminErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
	adminOKResponse(w, "OK")
	incMetric(metricAdminOK)
}

// Handler for POST requests to run file carves
func carvesRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var c DistributedCarveRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, true, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Path can not be empty
	if c.Path == "" {
		adminErrorResponse(w, "path can not be empty", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	query := generateCarveQuery(c.Path, false)
	// Prepare and create new carve
	carveName := generateCarveName()
	newQuery := queries.DistributedQuery{
		Query:      query,
		Name:       carveName,
		Creator:    ctx[ctxUser],
		Expected:   0,
		Executions: 0,
		Active:     true,
		Completed:  false,
		Deleted:    false,
		Type:       queries.CarveQueryType,
		Path:       c.Path,
	}
	if err := queriesmgr.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating carve", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(c.Environments) > 0 {
		for _, e := range c.Environments {
			if (e != "") && envs.Exists(e) {
				if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetEnvironment, e); err != nil {
					adminErrorResponse(w, "error creating carve environment target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.UUID)
				}
			}
		}
	}
	// Create platform target
	if len(c.Platforms) > 0 {
		for _, p := range c.Platforms {
			if (p != "") && checkValidPlatform(p) {
				if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetPlatform, p); err != nil {
					adminErrorResponse(w, "error creating carve platform target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				for _, n := range nodes {
					expected = append(expected, n.UUID)
				}
			}
		}
	}
	// Create UUIDs target
	if len(c.UUIDs) > 0 {
		for _, u := range c.UUIDs {
			if (u != "") && nodesmgr.CheckByUUID(u) {
				if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetUUID, u); err != nil {
					adminErrorResponse(w, "error creating carve UUID target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				expected = append(expected, u)
			}
		}
	}
	// Create hostnames target
	if len(c.Hosts) > 0 {
		for _, h := range c.Hosts {
			if (h != "") && nodesmgr.CheckByHost(h) {
				if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetLocalname, h); err != nil {
					adminErrorResponse(w, "error creating carve hostname target", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := queriesmgr.SetExpected(carveName, len(expectedClear)); err != nil {
		adminErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve run response sent")
	}
	adminOKResponse(w, "OK")
	incMetric(metricAdminOK)
}

// Handler for POST requests to queries
func queryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedQueryActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions for query
	if !checkPermissions(ctx[ctxUser], true, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.Names {
			if err := queriesmgr.Delete(n); err != nil {
				adminErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries delete successfully")
	case "complete":
		for _, n := range q.Names {
			if err := queriesmgr.Complete(n); err != nil {
				adminErrorResponse(w, "error completing query", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries completed successfully")
	case "activate":
		for _, n := range q.Names {
			if err := queriesmgr.Activate(n); err != nil {
				adminErrorResponse(w, "error activating query", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries activated successfully")
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
	incMetric(metricAdminOK)
}

// Handler for POST requests to carves
func carvesActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedCarvesActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, true, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.IDs {
			if err := carvesmgr.Delete(n); err != nil {
				adminErrorResponse(w, "error deleting carve", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "carves delete successfully")
	case "test":
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: testing action")
		}
		adminOKResponse(w, "test successful")
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carves action response sent")
	}
	incMetric(metricAdminOK)
}

// Handler POST requests for saving configuration
func confPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	environmentVar, ok := vars["environment"]
	if !ok || !envs.Exists(environmentVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	var c ConfigurationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, true, environmentVar) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	if c.ConfigurationB64 == "" {
		responseMessage := "empty configuration"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Decode received configuration
	configuration, err := base64.StdEncoding.DecodeString(c.ConfigurationB64)
	if err != nil {
		adminErrorResponse(w, "error decoding configuration", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Update configuration
	if err := envs.UpdateConfiguration(environmentVar, string(configuration)); err != nil {
		adminErrorResponse(w, "error saving configuration", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
	adminOKResponse(w, "configuration saved successfully")
	incMetric(metricAdminOK)
}

// Handler POST requests for saving intervals
func intervalsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	environmentVar, ok := vars["environment"]
	if !ok || !envs.Exists(environmentVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	var c IntervalsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, true, environmentVar) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	if err := envs.UpdateIntervals(environmentVar, c.ConfigInterval, c.LogInterval, c.QueryInterval); err != nil {
		adminErrorResponse(w, "error updating intervals", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// After updating interval, you need to re-generate flags
	flags, err := envs.GenerateFlagsEnv(environmentVar, "", "")
	if err != nil {
		adminErrorResponse(w, "error re-generating flags", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Update flags in the newly created environment
	if err := envs.UpdateFlags(environmentVar, flags); err != nil {
		adminErrorResponse(w, "error updating flags", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Intervals response sent")
	}
	adminOKResponse(w, "intervals saved successfully")
	incMetric(metricAdminOK)
}

// Handler POST requests for expiring enroll links
func expirationPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	environmentVar, ok := vars["environment"]
	if !ok || !envs.Exists(environmentVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	var e ExpirationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, true, environmentVar) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch e.Type {
	case "enroll":
		switch e.Action {
		case "expire":
			if err := envs.ExpireEnroll(environmentVar); err != nil {
				adminErrorResponse(w, "error expiring enroll", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case "extend":
			if err := envs.RotateEnrollPath(environmentVar); err != nil {
				adminErrorResponse(w, "error extending enroll", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			adminOKResponse(w, "link extended successfully")
		}
	case "remove":
		switch e.Action {
		case "expire":
			if err := envs.ExpireRemove(environmentVar); err != nil {
				adminErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case "extend":
			if err := envs.RotateRemove(environmentVar); err != nil {
				adminErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			adminOKResponse(w, "link extended successfully")
		}
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Expiration response sent")
	}
	incMetric(metricAdminOK)
}

// Handler POST requests for multi node action
func nodeActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var m NodeMultiActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], m.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch m.Action {
	case "delete":
		okCount := 0
		errCount := 0
		for _, u := range m.UUIDs {
			if err := nodesmgr.ArchiveDeleteByUUID(u); err != nil {
				errCount++
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: error deleting node %s %v", u, err)
				}
			} else {
				okCount++
			}
		}
		if errCount == 0 {
			adminOKResponse(w, fmt.Sprintf("%d Node(s) have been deleted successfully", okCount))
		} else {
			adminErrorResponse(w, fmt.Sprintf("Error deleting %d node(s)", errCount), http.StatusInternalServerError, nil)
			incMetric(metricAdminErr)
			return
		}
	case "archive":
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: archiving node")
		}
		adminOKResponse(w, "node archived successfully")
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Multi-node action response sent")
	}
	incMetric(metricAdminOK)
}

// Handler for POST request for /environments
func envsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var c EnvironmentsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch c.Action {
	case "create":
		// FIXME verify fields
		if !envs.Exists(c.Name) {
			env := envs.Empty(c.Name, c.Hostname)
			env.Icon = c.Icon
			env.Type = c.Type
			if env.Configuration == "" {
				env.Configuration = environments.ReadExternalFile(emptyConfiguration)
			}
			if env.Flags == "" {
				// Generate flags
				flags, err := environments.GenerateFlags(env, "", "")
				if err != nil {
					adminErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				env.Flags = flags
			}
			if err := envs.Create(env); err != nil {
				adminErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "environment created successfully")
	case "delete":
		if c.Name == settingsmgr.DefaultEnv(settings.ServiceAdmin) {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to remove enviornment %s", c.Name))
			incMetric(metricAdminErr)
			return
		}
		if envs.Exists(c.Name) {
			if err := envs.Delete(c.Name); err != nil {
				adminErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "environment deleted successfully")
	case "debug":
		// FIXME verify fields
		if envs.Exists(c.Name) {
			if err := envs.ChangeDebugHTTP(c.Name, c.DebugHTTP); err != nil {
				adminErrorResponse(w, "error changing DebugHTTP", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "debug changed successfully")
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Environments response sent")
	}
	incMetric(metricAdminOK)
}

// Handler for POST request for /settings
func settingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		adminErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// Verify service
	if !checkTargetService(serviceVar) {
		adminErrorResponse(w, fmt.Sprintf("unknown service (%s)", serviceVar), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	var s SettingsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], s.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch s.Action {
	case "add":
		if !settingsmgr.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			incMetric(metricAdminErr)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = settingsmgr.NewBooleanValue(serviceVar, s.Name, stringToBoolean(s.Value))
		case settings.TypeInteger:
			err = settingsmgr.NewIntegerValue(serviceVar, s.Name, stringToInteger(s.Value))
		case settings.TypeString:
			err = settingsmgr.NewStringValue(serviceVar, s.Name, s.Value)
		}
		if err != nil {
			adminErrorResponse(w, "error adding setting", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting added successfully")
	case "change":
		if !settingsmgr.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			incMetric(metricAdminErr)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = settingsmgr.SetBoolean(s.Boolean, serviceVar, s.Name)
		case settings.TypeInteger:
			err = settingsmgr.SetInteger(stringToInteger(s.Value), serviceVar, s.Name)
		case settings.TypeString:
			err = settingsmgr.SetString(s.Value, serviceVar, s.Name, false)
		}
		if err != nil {
			adminErrorResponse(w, "error changing setting", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting changed successfully")
	case "delete":
		if err := settingsmgr.DeleteValue(serviceVar, s.Name); err != nil {
			adminErrorResponse(w, "error deleting setting", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting deleted successfully")
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Settings response sent")
	}
	incMetric(metricAdminOK)
}

// Handler for POST request for /users
func usersPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], u.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	switch u.Action {
	case "add":
		// FIXME password complexity?
		if adminUsers.Exists(u.Username) {
			adminErrorResponse(w, "error adding user", http.StatusInternalServerError, fmt.Errorf("user %s already exists", u.Username))
			incMetric(metricAdminErr)
			return
		}
		// Prepare user to create
		newUser, err := adminUsers.New(u.Username, u.Password, u.Email, u.Fullname, u.Admin)
		if err != nil {
			adminErrorResponse(w, "error with new user", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
			return
		}
		// Create new user
		if err = adminUsers.Create(newUser); err != nil {
			adminErrorResponse(w, "error creating user", http.StatusInternalServerError, err)
			incMetric(metricAdminErr)
			return
		}
		if u.Admin {
			namesEnvs, err := envs.Names()
			if err != nil {
				adminErrorResponse(w, "error getting environments user", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			perms := adminUsers.GenPermissions(namesEnvs, u.Admin)
			if err := adminUsers.ChangePermissions(u.Username, perms); err != nil {
				adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		if u.Token {
			token, exp, err := adminUsers.CreateToken(newUser.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
			if err != nil {
				adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			if err = adminUsers.UpdateToken(newUser.Username, token, exp); err != nil {
				adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user added successfully")
	case "edit":
		if u.Fullname != "" {
			if err := adminUsers.ChangeFullname(u.Username, u.Fullname); err != nil {
				adminErrorResponse(w, "error changing fullname", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		if u.Email != "" {
			if err := adminUsers.ChangeEmail(u.Username, u.Email); err != nil {
				adminErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user updated successfully")
	case "remove":
		if u.Username == ctx[ctxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to remove current user %s", u.Username))
			incMetric(metricAdminErr)
			return
		}
		if adminUsers.Exists(u.Username) {
			if err := adminUsers.Delete(u.Username); err != nil {
				adminErrorResponse(w, "error removing user", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user removed successfully")
	case "admin":
		if u.Username == ctx[ctxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to de-admin current user %s", u.Username))
			incMetric(metricAdminErr)
			return
		}
		if adminUsers.Exists(u.Username) {
			if err := adminUsers.ChangeAdmin(u.Username, u.Admin); err != nil {
				adminErrorResponse(w, "error changing admin", http.StatusInternalServerError, err)
				incMetric(metricAdminErr)
				return
			}
			if u.Admin {
				namesEnvs, err := envs.Names()
				if err != nil {
					adminErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				perms := adminUsers.GenPermissions(namesEnvs, u.Admin)
				if err := adminUsers.ChangePermissions(u.Username, perms); err != nil {
					adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				token, exp, err := adminUsers.CreateToken(u.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
				if err != nil {
					adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
				if err := adminUsers.UpdateToken(u.Username, token, exp); err != nil {
					adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
					incMetric(metricAdminErr)
					return
				}
			}
			adminOKResponse(w, "admin changed successfully")
		}
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
	incMetric(metricAdminOK)
}

// Handler for POST request for /users/permissions
func permissionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract username and verify
	usernameVar, ok := vars["username"]
	if !ok || !adminUsers.Exists(usernameVar) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	var p PermissionsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, false, "") {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], p.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	// TODO verify environments
	perms := users.UserPermissions{
		Environments: p.Environments,
		Query:        p.Query,
		Carve:        p.Carve,
	}
	if err := adminUsers.ChangePermissions(usernameVar, perms); err != nil {
		adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
	adminOKResponse(w, "OK")
	incMetric(metricAdminOK)
}

// Handler POST requests enroll data
func enrollPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	environmentVar, ok := vars["environment"]
	if !ok || !envs.Exists(environmentVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	var e EnrollRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkPermissions(ctx[ctxUser], false, false, true, environmentVar) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser]), http.StatusForbidden, nil)
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	if e.CertificateB64 == "" {
		adminErrorResponse(w, "empty certificate", http.StatusInternalServerError, nil)
		incMetric(metricAdminErr)
		return
	}
	certificate, err := base64.StdEncoding.DecodeString(e.CertificateB64)
	if err != nil {
		adminErrorResponse(w, "error decoding certificate", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	if err := envs.UpdateCertificate(environmentVar, string(certificate)); err != nil {
		adminErrorResponse(w, "error saving certificate", http.StatusInternalServerError, err)
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
	adminOKResponse(w, "enroll data saved")
	incMetric(metricAdminOK)
}
