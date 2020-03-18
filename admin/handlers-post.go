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
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check credentials
	access, user := adminUsers.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		responseMessage := "invalid credentials"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	_, err := sessionsmgr.Save(r, w, user)
	if err != nil {
		responseMessage := "session error"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "OK"})
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
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], l.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Destroy existing session
	if err := sessionsmgr.Destroy(r); err != nil {
		responseMessage := "error destroying session"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Logout response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "OK"})
	incMetric(metricAdminOK)
}

// Handler for POST requests to run queries
func queryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedQueryRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		responseMessage := "query can not be empty"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Prepare and create new query
	newQuery := newQueryReady(ctx[ctxUser], q.Query)
	if err := queriesmgr.Create(newQuery); err != nil {
		responseMessage := "error creating query"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
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
					responseMessage := "error creating query environment target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					responseMessage := "error getting nodes by environment"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating query platform target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					responseMessage := "error getting nodes by platform"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating query UUID target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating query hostname target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
		responseMessage := "error setting expected"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "OK"})
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
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Path can not be empty
	if c.Path == "" {
		responseMessage := "path can not be empty"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
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
		responseMessage := "error creating carve"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
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
					responseMessage := "error creating carve environment target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByEnv(e, "active", settingsmgr.InactiveHours())
				if err != nil {
					responseMessage := "error getting nodes by environment"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating carve platform target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				nodes, err := nodesmgr.GetByPlatform(p, "active", settingsmgr.InactiveHours())
				if err != nil {
					responseMessage := "error getting nodes by platform"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating carve UUID target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
					responseMessage := "error creating carve hostname target"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
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
		responseMessage := "error setting expected"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve run response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "OK"})
	incMetric(metricAdminOK)
}

// Handler for POST requests to queries
func queryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedQueryActionRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.Names {
			if err := queriesmgr.Delete(n); err != nil {
				responseMessage := "error deleting query"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Queries deleted successfully"})
	case "complete":
		for _, n := range q.Names {
			if err := queriesmgr.Complete(n); err != nil {
				responseMessage := "error completing query"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Queries completed successfully"})
	case "activate":
		for _, n := range q.Names {
			if err := queriesmgr.Activate(n); err != nil {
				responseMessage := "error activating query"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Queries activated successfully"})
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
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], q.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.IDs {
			if err := carvesmgr.Delete(n); err != nil {
				responseMessage := "error deleting carve"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Carves deleted successfully"})
	case "test":
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: testing action")
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Test successful"})
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
		responseMessage := "error getting environment"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		responseMessage := fmt.Sprintf("unknown environment (%s)", environmentVar)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var c ConfigurationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
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
		responseMessage := "error decoding configuration"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Update configuration
	if err := envs.UpdateConfiguration(environmentVar, string(configuration)); err != nil {
		responseMessage := "error saving configuration"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Configuration saved successfully"})
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
		responseMessage := "error getting environment"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		responseMessage := fmt.Sprintf("unknown environment (%s)", environmentVar)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var c IntervalsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	if err := envs.UpdateIntervals(environmentVar, c.ConfigInterval, c.LogInterval, c.QueryInterval); err != nil {
		responseMessage := "error updating intervals"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// After updating interval, you need to re-generate flags
	flags, err := envs.GenerateFlagsEnv(environmentVar, "", "")
	if err != nil {
		responseMessage := "error re-generating flags"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Update flags in the newly created environment
	if err := envs.UpdateFlags(environmentVar, flags); err != nil {
		responseMessage := "error updating flags"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Intervals response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Intervals saved successfully"})
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
		responseMessage := "error getting environment"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		responseMessage := fmt.Sprintf("unknown environment (%s)", environmentVar)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var e ExpirationRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], e.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	switch e.Type {
	case "enroll":
		switch e.Action {
		case "expire":
			if err := envs.ExpireEnroll(environmentVar); err != nil {
				responseMessage := "error expiring enroll"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Link expired successfully"})
		case "extend":
			if err := envs.RotateEnrollPath(environmentVar); err != nil {
				responseMessage := "error extending enroll"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Link extended successfully"})
		}
	case "remove":
		switch e.Action {
		case "expire":
			if err := envs.ExpireRemove(environmentVar); err != nil {
				responseMessage := "error expiring enroll"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Link expired successfully"})
		case "extend":
			if err := envs.RotateRemove(environmentVar); err != nil {
				responseMessage := "error extending enroll"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Link extended successfully"})
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
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], m.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
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
			responseMessage := fmt.Sprintf("%d Node(s) have been deleted successfully", okCount)
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: responseMessage})
		} else {
			responseMessage := fmt.Sprintf("Error deleting %d node(s)", errCount)
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			incMetric(metricAdminErr)
			return
		}
	case "archive":
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: archiving node")
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Node archived successfully"})
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
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], c.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
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
					responseMessage := "error generating flags"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				env.Flags = flags
			}
			if err := envs.Create(env); err != nil {
				responseMessage := "error creating environment"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Environment created successfully"})
	case "delete":
		if c.Name == settingsmgr.DefaultEnv(settings.ServiceAdmin) {
			responseMessage := "Not a good idea"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			log.Println("Attempt to remove default environment")
			incMetric(metricAdminErr)
			return
		}
		if envs.Exists(c.Name) {
			if err := envs.Delete(c.Name); err != nil {
				responseMessage := "error deleting environment"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Environment deleted successfully"})
	case "debug":
		// FIXME verify fields
		if envs.Exists(c.Name) {
			if err := envs.ChangeDebugHTTP(c.Name, c.DebugHTTP); err != nil {
				responseMessage := "error changing DebugHTTP"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "DebugHTTP changed successfully"})
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
		responseMessage := "error getting service"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Verify service
	if !checkTargetService(serviceVar) {
		responseMessage := fmt.Sprintf("unknown service (%s)", serviceVar)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var s SettingsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], s.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	switch s.Action {
	case "add":
		if !settingsmgr.VerifyType(s.Type) {
			responseMessage := "invalid type"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s", responseMessage)
			}
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
			responseMessage := "error adding setting"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
			incMetric(metricAdminErr)
			return
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Setting added successfully"})
	case "change":
		if !settingsmgr.VerifyType(s.Type) {
			responseMessage := "invalid type"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s", responseMessage)
			}
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
			responseMessage := "error changing setting"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
			incMetric(metricAdminErr)
			return
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Setting changed successfully"})
	case "delete":
		if err := settingsmgr.DeleteValue(serviceVar, s.Name); err != nil {
			responseMessage := "error deleting setting"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
			incMetric(metricAdminErr)
			return
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Setting deleted successfully"})
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
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], u.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	switch u.Action {
	case "add":
		// FIXME password complexity?
		if adminUsers.Exists(u.Username) {
			responseMessage := "user already exists"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s", responseMessage)
			}
			incMetric(metricAdminErr)
			return
		}
		// Prepare user to create
		newUser, err := adminUsers.New(u.Username, u.Password, u.Email, u.Fullname, u.Admin)
		if err != nil {
			responseMessage := "error with new user"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
			incMetric(metricAdminErr)
			return
		}
		// Create new user
		if err = adminUsers.Create(newUser); err != nil {
			responseMessage := "error creating user"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Printf("DebugService: %s %v", responseMessage, err)
			}
			incMetric(metricAdminErr)
			return
		}
		if u.Admin {
			namesEnvs, err := envs.Names()
			if err != nil {
				responseMessage := "error getting environments"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			perms := adminUsers.GenPermissions(namesEnvs, u.Admin)
			if err := adminUsers.ChangePermissions(u.Username, perms); err != nil {
				responseMessage := "error changing permissions"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		if u.Token {
			token, exp, err := adminUsers.CreateToken(newUser.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
			if err != nil {
				responseMessage := "error creating token"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			if err = adminUsers.UpdateToken(newUser.Username, token, exp); err != nil {
				responseMessage := "error saving token"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "User added successfully"})
	case "edit":
		if u.Fullname != "" {
			if err := adminUsers.ChangeFullname(u.Username, u.Fullname); err != nil {
				responseMessage := "error changing fullname"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		if u.Email != "" {
			if err := adminUsers.ChangeEmail(u.Username, u.Email); err != nil {
				responseMessage := "error changing email"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "User updated successfully"})
	case "remove":
		if u.Username == ctx[ctxUser] {
			responseMessage := "Not a good idea"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			log.Printf("Attempt to self remove by %s", ctx[ctxUser])
			incMetric(metricAdminErr)
			return
		} else if adminUsers.Exists(u.Username) {
			if err := adminUsers.Delete(u.Username); err != nil {
				responseMessage := "error removing user"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
		}
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "User removed"})
	case "admin":
		if u.Username == ctx[ctxUser] {
			responseMessage := "Not a good idea"
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
			log.Printf("Attempt to change admin by %s", ctx[ctxUser])
			incMetric(metricAdminErr)
			return
		} else if adminUsers.Exists(u.Username) {
			if err := adminUsers.ChangeAdmin(u.Username, u.Admin); err != nil {
				responseMessage := "error changing admin"
				utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: %s %v", responseMessage, err)
				}
				incMetric(metricAdminErr)
				return
			}
			if u.Admin {
				namesEnvs, err := envs.Names()
				if err != nil {
					responseMessage := "error getting environments"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				perms := adminUsers.GenPermissions(namesEnvs, u.Admin)
				if err := adminUsers.ChangePermissions(u.Username, perms); err != nil {
					responseMessage := "error changing permissions"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				token, exp, err := adminUsers.CreateToken(u.Username, jwtConfig.HoursToExpire, jwtConfig.JWTSecret)
				if err != nil {
					responseMessage := "error creating token"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
				if err := adminUsers.UpdateToken(u.Username, token, exp); err != nil {
					responseMessage := "error saving token"
					utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Printf("DebugService: %s %v", responseMessage, err)
					}
					incMetric(metricAdminErr)
					return
				}
			}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Admin changed successfully"})
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
		responseMessage := "error getting username"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var p PermissionsRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], p.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
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
		responseMessage := "error changing permissions"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "OK"})
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
		responseMessage := "error getting environment"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Verify environment
	if !envs.Exists(environmentVar) {
		responseMessage := fmt.Sprintf("unknown environment (%s)", environmentVar)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	var e EnrollRequest
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Check permissions
	if !checkAdminLevel(ctx[ctxLevel]) {
		responseMessage := fmt.Sprintf("%s has insuficient permissions", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusForbidden, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	// Parse request JSON body
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		responseMessage := "error parsing POST body"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !checkCSRFToken(ctx[ctxCSRF], e.CSRFToken) {
		responseMessage := "invalid CSRF token"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	if e.CertificateB64 == "" {
		responseMessage := "empty certificate"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s", responseMessage)
		}
		incMetric(metricAdminErr)
		return
	}
	certificate, err := base64.StdEncoding.DecodeString(e.CertificateB64)
	if err != nil {
		responseMessage := "error decoding certificate"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	if err := envs.UpdateCertificate(environmentVar, string(certificate)); err != nil {
		responseMessage := "error saving certificate"
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: %s %v", responseMessage, err)
		}
		incMetric(metricAdminErr)
		return
	}
	// Serialize and send response
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, AdminResponse{Message: "Enroll data saved successfully"})
	incMetric(metricAdminOK)
}
