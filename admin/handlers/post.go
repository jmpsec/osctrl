package handlers

import (
	"encoding/base64"
	"encoding/json"

	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// LoginPOSTHandler for login page for POST requests
func (h *HandlersAdmin) LoginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	var l LoginRequest
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check credentials
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		adminErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	envAccess, err := h.Users.GetEnvAccess(user.Username, user.DefaultEnv)
	if err != nil {
		adminErrorResponse(w, "error processing login", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	_, err = h.Sessions.Save(r, w, user, envAccess)
	if err != nil {
		adminErrorResponse(w, "session error", http.StatusForbidden, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login response sent")
	}
	adminOKResponse(w, "/environment/"+user.DefaultEnv+"/active")
	h.Inc(metricAdminOK)
}

// LogoutPOSTHandler for POST requests to logout
func (h *HandlersAdmin) LogoutPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	var l LogoutRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], l.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Destroy existing session
	if err := h.Sessions.Destroy(r); err != nil {
		adminErrorResponse(w, "error destroying session", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Logout response sent")
	}
	adminOKResponse(w, "OK")
	h.Inc(metricAdminOK)
}

// QueryRunPOSTHandler for POST requests to run queries
func (h *HandlersAdmin) QueryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		log.Println("environment is missing")
		h.Inc(metricAdminErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Printf("error getting environment %s - %v", envVar, err)
		h.Inc(metricAdminErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions for query
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	var q DistributedQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		adminErrorResponse(w, "query can not be empty", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// FIXME check if query is carve and user has permissions to carve
	// Prepare and create new query
	newQuery := newQueryReady(ctx[sessions.CtxUser], q.Query, env.ID)
	if err := h.Queries.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(q.Environments) > 0 {
		for _, e := range q.Environments {
			if (e != "") && h.Envs.Exists(e) {
				if err := h.Queries.CreateTarget(newQuery.Name, queries.QueryTargetEnvironment, e); err != nil {
					adminErrorResponse(w, "error creating query environment target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
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
					adminErrorResponse(w, "error creating query platform target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				nodes, err := h.Nodes.GetByPlatform(p, "active", h.Settings.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
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
					adminErrorResponse(w, "error creating query UUID target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
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
					adminErrorResponse(w, "error creating query hostname target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				expected = append(expected, _h)
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := h.Queries.SetExpected(newQuery.Name, len(expectedClear), env.ID); err != nil {
		adminErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Save query if requested and if the name is not empty
	if q.Save && q.Name != "" {
		if err := h.Queries.CreateSaved(q.Name, q.Query, ctx[sessions.CtxUser], env.ID); err != nil {
			adminErrorResponse(w, "error saving query", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
	adminOKResponse(w, "OK")
	h.Inc(metricAdminOK)
}

// CarvesRunPOSTHandler for POST requests to run file carves
func (h *HandlersAdmin) CarvesRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		log.Println("environment is missing")
		h.Inc(metricAdminErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Printf("error getting environment %s - %v", envVar, err)
		h.Inc(metricAdminErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	var c DistributedCarveRequest
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// FIXME check validity of query
	// Path can not be empty
	if c.Path == "" {
		adminErrorResponse(w, "path can not be empty", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	query := generateCarveQuery(c.Path, false)
	// Prepare and create new carve
	carveName := generateCarveName()
	newQuery := queries.DistributedQuery{
		Query:         query,
		Name:          carveName,
		Creator:       ctx[sessions.CtxUser],
		Expected:      0,
		Executions:    0,
		Active:        true,
		Completed:     false,
		Deleted:       false,
		Type:          queries.CarveQueryType,
		Path:          c.Path,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating carve", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Temporary list of UUIDs to calculate Expected
	var expected []string
	// Create environment target
	if len(c.Environments) > 0 {
		for _, e := range c.Environments {
			if (e != "") && h.Envs.Exists(e) {
				if err := h.Queries.CreateTarget(carveName, queries.QueryTargetEnvironment, e); err != nil {
					adminErrorResponse(w, "error creating carve environment target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
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
		platforms, _ := h.Nodes.GetAllPlatforms()
		for _, p := range c.Platforms {
			if (p != "") && checkValidPlatform(platforms, p) {
				if err := h.Queries.CreateTarget(carveName, queries.QueryTargetPlatform, p); err != nil {
					adminErrorResponse(w, "error creating carve platform target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				nodes, err := h.Nodes.GetByPlatform(p, "active", h.Settings.InactiveHours())
				if err != nil {
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
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
			if (u != "") && h.Nodes.CheckByUUID(u) {
				if err := h.Queries.CreateTarget(carveName, queries.QueryTargetUUID, u); err != nil {
					adminErrorResponse(w, "error creating carve UUID target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				expected = append(expected, u)
			}
		}
	}
	// Create hostnames target
	if len(c.Hosts) > 0 {
		for _, _h := range c.Hosts {
			if (_h != "") && h.Nodes.CheckByHost(_h) {
				if err := h.Queries.CreateTarget(carveName, queries.QueryTargetLocalname, _h); err != nil {
					adminErrorResponse(w, "error creating carve hostname target", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
			}
		}
	}
	// Remove duplicates from expected
	expectedClear := removeStringDuplicates(expected)
	// Update value for expected
	if err := h.Queries.SetExpected(carveName, len(expectedClear), env.ID); err != nil {
		adminErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve run response sent")
	}
	adminOKResponse(w, "OK")
	h.Inc(metricAdminOK)
}

// QueryActionsPOSTHandler for POST requests to queries
func (h *HandlersAdmin) QueryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		log.Println("environment is missing")
		h.Inc(metricAdminErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Printf("error getting environment %s - %v", envVar, err)
		h.Inc(metricAdminErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions for query
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	var q DistributedQueryActionRequest
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.Names {
			if err := h.Queries.Delete(n, env.ID); err != nil {
				adminErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries delete successfully")
	case "complete":
		for _, n := range q.Names {
			if err := h.Queries.Complete(n, env.ID); err != nil {
				adminErrorResponse(w, "error completing query", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries completed successfully")
	case "activate":
		for _, n := range q.Names {
			if err := h.Queries.Activate(n, env.ID); err != nil {
				adminErrorResponse(w, "error activating query", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries activated successfully")
	case "saved_delete":
		for _, n := range q.Names {
			if err := h.Queries.DeleteSaved(n, ctx[sessions.CtxUser], env.ID); err != nil {
				adminErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "queries delete successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run response sent")
	}
	h.Inc(metricAdminOK)
}

// CarvesActionsPOSTHandler - Handler for POST requests to carves
func (h *HandlersAdmin) CarvesActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var q DistributedCarvesActionRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.IDs {
			if err := h.Carves.Delete(n); err != nil {
				adminErrorResponse(w, "error deleting carve", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "carves delete successfully")
	case "test":
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: testing action")
		}
		adminOKResponse(w, "test successful")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carves action response sent")
	}
	h.Inc(metricAdminOK)
}

// ConfPOSTHandler for POST requests for saving configuration
func (h *HandlersAdmin) ConfPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error getting environment: %v", err)
		return
	}
	var c ConfigurationRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	if c.ConfigurationB64 != "" {
		// Base64 decode received configuration
		// TODO verify configuration
		configuration, err := base64.StdEncoding.DecodeString(c.ConfigurationB64)
		if err != nil {
			adminErrorResponse(w, "error decoding configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Parse configuration
		cnf, err := h.Envs.GenStructConf(configuration)
		if err != nil {
			adminErrorResponse(w, "error parsing configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update configuration
		if err := h.Envs.UpdateConfiguration(env.UUID, cnf); err != nil {
			adminErrorResponse(w, "error saving configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update all configuration parts
		if err := h.Envs.UpdateConfigurationParts(env.UUID, cnf); err != nil {
			adminErrorResponse(w, "error saving configuration parts", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: Configuration response sent")
		}
		adminOKResponse(w, "configuration saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	if c.OptionsB64 != "" {
		// Base64 decode received options
		// TODO verify options
		options, err := base64.StdEncoding.DecodeString(c.OptionsB64)
		if err != nil {
			adminErrorResponse(w, "error decoding options", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update options
		if err := h.Envs.UpdateOptions(env.UUID, string(options)); err != nil {
			adminErrorResponse(w, "error saving options", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: Options response sent")
		}
		adminOKResponse(w, "options saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	if c.ScheduleB64 != "" {
		// TODO verify schedule
		// Decode received configuration
		schedule, err := base64.StdEncoding.DecodeString(c.ScheduleB64)
		if err != nil {
			adminErrorResponse(w, "error decoding schedule", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update schedule
		if err := h.Envs.UpdateSchedule(env.UUID, string(schedule)); err != nil {
			adminErrorResponse(w, "error saving schedule", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: Schedule response sent")
		}
		adminOKResponse(w, "schedule saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	if c.PacksB64 != "" {
		// TODO verify packs
		// Base64 decode received packs
		packs, err := base64.StdEncoding.DecodeString(c.PacksB64)
		if err != nil {
			adminErrorResponse(w, "error decoding packs", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update packs
		if err := h.Envs.UpdatePacks(env.UUID, string(packs)); err != nil {
			adminErrorResponse(w, "error saving packs", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: Packs response sent")
		}
		adminOKResponse(w, "packs saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	if c.DecoratorsB64 != "" {
		// Base64 decode received options
		// TODO verify decorators
		decorators, err := base64.StdEncoding.DecodeString(c.DecoratorsB64)
		if err != nil {
			adminErrorResponse(w, "error decoding decorators", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update decorators
		if err := h.Envs.UpdateDecorators(env.UUID, string(decorators)); err != nil {
			adminErrorResponse(w, "error saving decorators", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: Decorators response sent")
		}
		adminOKResponse(w, "decorators saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	if c.ATCB64 != "" {
		// TODO verify ATC
		// Base64 decode received ATC
		schedule, err := base64.StdEncoding.DecodeString(c.ATCB64)
		if err != nil {
			adminErrorResponse(w, "error decoding ATC", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update ATC
		if err := h.Envs.UpdateATC(env.UUID, string(schedule)); err != nil {
			adminErrorResponse(w, "error saving ATC", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Send response
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: ATC response sent")
		}
		adminOKResponse(w, "ATC saved successfully")
		h.Inc(metricAdminOK)
		return
	}
	// If we are here, means that the request received was empty
	responseMessage := "empty configuration"
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Printf("DebugService: %s", responseMessage)
	}
	h.Inc(metricAdminErr)
}

// IntervalsPOSTHandler for POST requests for saving intervals
func (h *HandlersAdmin) IntervalsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment and verify
	envVar, ok := vars["environment"]
	if !ok || !h.Envs.Exists(envVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// TODO do the exist and get in one step
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	var c IntervalsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	if err := h.Envs.UpdateIntervals(env.Name, c.ConfigInterval, c.LogInterval, c.QueryInterval); err != nil {
		adminErrorResponse(w, "error updating intervals", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// After updating interval, you need to re-generate flags
	flags, err := h.Envs.GenerateFlagsEnv(envVar, "", "")
	if err != nil {
		adminErrorResponse(w, "error re-generating flags", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Update flags in the newly created environment
	if err := h.Envs.UpdateFlags(envVar, flags); err != nil {
		adminErrorResponse(w, "error updating flags", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Intervals response sent")
	}
	adminOKResponse(w, "intervals saved successfully")
	h.Inc(metricAdminOK)
}

// ExpirationPOSTHandler for POST requests for expiring enroll links
func (h *HandlersAdmin) ExpirationPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error getting environment: %v", err)
		return
	}
	var e ExpirationRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch e.Type {
	case settings.ScriptEnroll:
		switch e.Action {
		case "expire":
			if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error expiring enroll", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case "extend":
			if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error extending enroll", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link extended successfully")
		case "rotate":
			if err := h.Envs.RotateEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error rotating enroll", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link rotated successfully")
		case "notexpire":
			if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error not expiring enroll", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link set to not expire successfully")
		}
	case settings.ScriptRemove:
		switch e.Action {
		case "expire":
			if err := h.Envs.ExpireRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case "extend":
			if err := h.Envs.ExtendRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link extended successfully")
		case "rotate":
			if err := h.Envs.RotateRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link rotated successfully")
		case "notexpire":
			if err := h.Envs.NotExpireRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error not expiring remove", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "link set to not expire successfully")
		}
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Expiration response sent")
	}
	h.Inc(metricAdminOK)
}

// NodeActionsPOSTHandler for POST requests for multi node action
func (h *HandlersAdmin) NodeActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var m NodeMultiActionRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], m.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch m.Action {
	case "delete":
		okCount := 0
		errCount := 0
		for _, u := range m.UUIDs {
			if err := h.Nodes.ArchiveDeleteByUUID(u); err != nil {
				errCount++
				if h.Settings.DebugService(settings.ServiceAdmin) {
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
			h.Inc(metricAdminErr)
			return
		}
	case "archive":
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: archiving node")
		}
		adminOKResponse(w, "node archived successfully")
	case "tag":
		okCount := 0
		errCount := 0
		for _, u := range m.UUIDs {
			if err := h.Nodes.ArchiveDeleteByUUID(u); err != nil {
				errCount++
				if h.Settings.DebugService(settings.ServiceAdmin) {
					log.Printf("DebugService: error tagging node %s %v", u, err)
				}
			} else {
				okCount++
			}
		}
		if errCount == 0 {
			adminOKResponse(w, fmt.Sprintf("%d Node(s) have been deleted successfully", okCount))
		} else {
			adminErrorResponse(w, fmt.Sprintf("Error deleting %d node(s)", errCount), http.StatusInternalServerError, nil)
			h.Inc(metricAdminErr)
			return
		}
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Multi-node action response sent")
	}
	h.Inc(metricAdminOK)
}

// EnvsPOSTHandler for POST request for /environments
func (h *HandlersAdmin) EnvsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var c EnvironmentsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch c.Action {
	case "create":
		// FIXME verify fields
		if !h.Envs.Exists(c.Name) && c.Name != "" {
			env := h.Envs.Empty(c.Name, c.Hostname)
			env.Icon = c.Icon
			env.Type = c.Type
			// Emtpy configuration
			env.Configuration = h.Envs.GenEmptyConfiguration(true)
			// Generate flags
			flags, err := h.Envs.GenerateFlags(env, "", "")
			if err != nil {
				adminErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			env.Flags = flags
			if err := h.Envs.Create(env); err != nil {
				adminErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			// Generate full permissions for the user creating the environment
			access := h.Users.GenEnvUserAccess([]string{env.UUID}, true, true, true, true)
			perms := h.Users.GenPermissions(ctx[sessions.CtxUser], "osctrl-admin", access)
			if err := h.Users.CreatePermissions(perms); err != nil {
				adminErrorResponse(w, "error generating permissions", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			// Create a tag for this new environment
			if err := h.Tags.NewTag(env.Name, "Tag for environment "+env.Name, "", env.Icon, ctx[sessions.CtxUser]); err != nil {
				adminErrorResponse(w, "error generating tag", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			adminOKResponse(w, "environment created successfully")
		} else {
			adminOKResponse(w, "invalid environment")
			h.Inc(metricAdminErr)
			return
		}
	case "delete":
		if c.Name == h.Settings.DefaultEnv(settings.ServiceAdmin) {
			adminErrorResponse(w, "nope, this is the default environment", http.StatusInternalServerError, fmt.Errorf("attempt to remove default environment %s", c.Name))
			h.Inc(metricAdminErr)
			return
		}
		if h.Envs.Exists(c.Name) {
			if err := h.Envs.Delete(c.Name); err != nil {
				adminErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "environment deleted successfully")
	case "debug":
		// FIXME verify fields
		if h.Envs.Exists(c.Name) {
			if err := h.Envs.ChangeDebugHTTP(c.Name, c.DebugHTTP); err != nil {
				adminErrorResponse(w, "error changing DebugHTTP", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "debug changed successfully")
	case "edit":
		if h.Envs.Exists(c.UUID) {
			if err := h.Envs.UpdateHostname(c.UUID, c.Hostname); err != nil {
				adminErrorResponse(w, "error updating hostname", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "debug changed successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Environments response sent")
	}
	h.Inc(metricAdminOK)
}

// SettingsPOSTHandler for POST request for /settings
func (h *HandlersAdmin) SettingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		adminErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Verify service
	if !checkTargetService(serviceVar) {
		adminErrorResponse(w, fmt.Sprintf("unknown service (%s)", serviceVar), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	var s SettingsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], s.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch s.Action {
	case "add":
		if !h.Settings.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			h.Inc(metricAdminErr)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = h.Settings.NewBooleanValue(serviceVar, s.Name, utils.StringToBoolean(s.Value))
		case settings.TypeInteger:
			err = h.Settings.NewIntegerValue(serviceVar, s.Name, utils.StringToInteger(s.Value))
		case settings.TypeString:
			err = h.Settings.NewStringValue(serviceVar, s.Name, s.Value)
		}
		if err != nil {
			adminErrorResponse(w, "error adding setting", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting added successfully")
	case "change":
		if !h.Settings.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			h.Inc(metricAdminErr)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = h.Settings.SetBoolean(s.Boolean, serviceVar, s.Name)
		case settings.TypeInteger:
			err = h.Settings.SetInteger(utils.StringToInteger(s.Value), serviceVar, s.Name)
		case settings.TypeString:
			err = h.Settings.SetString(s.Value, serviceVar, s.Name, false)
		}
		if err != nil {
			adminErrorResponse(w, "error changing setting", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting changed successfully")
	case "delete":
		if err := h.Settings.DeleteValue(serviceVar, s.Name); err != nil {
			adminErrorResponse(w, "error deleting setting", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		adminOKResponse(w, "setting deleted successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Settings response sent")
	}
	h.Inc(metricAdminOK)
}

// UsersPOSTHandler for POST request for /users
func (h *HandlersAdmin) UsersPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], u.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch u.Action {
	case "add":
		// FIXME password complexity?
		if h.Users.Exists(u.Username) {
			adminErrorResponse(w, "error adding user", http.StatusInternalServerError, fmt.Errorf("user %s already exists", u.Username))
			h.Inc(metricAdminErr)
			return
		}
		// Check that default environment exists
		if (u.DefaultEnv == "") || !h.Envs.Exists(u.DefaultEnv) {
			adminErrorResponse(w, "error adding user", http.StatusInternalServerError, fmt.Errorf("environment %s does not exist", u.DefaultEnv))
			h.Inc(metricAdminErr)
			return
		}
		// Prepare user to create
		newUser, err := h.Users.New(u.Username, u.NewPassword, u.Email, u.Fullname, u.DefaultEnv, u.Admin)
		if err != nil {
			adminErrorResponse(w, "error with new user", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		// Create new user
		if err = h.Users.Create(newUser); err != nil {
			adminErrorResponse(w, "error creating user", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		/*
			if u.Admin {
				access = users.AdminLevel
				namesEnvs, err = h.Envs.Names()
				if err != nil {
					adminErrorResponse(w, "error getting environments user", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
			}
		*/
		access := h.Users.GenEnvUserAccess([]string{u.DefaultEnv}, true, (u.Admin == true), (u.Admin == true), (u.Admin == true))
		perms := h.Users.GenPermissions(u.Username, ctx[sessions.CtxUser], access)
		if err := h.Users.CreatePermissions(perms); err != nil {
			adminErrorResponse(w, "error creating permissions", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		if u.Token {
			token, exp, err := h.Users.CreateToken(newUser.Username)
			if err != nil {
				adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			if err = h.Users.UpdateToken(newUser.Username, token, exp); err != nil {
				adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user added successfully")
	case "edit":
		if u.Fullname != "" {
			if err := h.Users.ChangeFullname(u.Username, u.Fullname); err != nil {
				adminErrorResponse(w, "error changing fullname", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if u.Email != "" {
			if err := h.Users.ChangeEmail(u.Username, u.Email); err != nil {
				adminErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if u.DefaultEnv != "" && h.Envs.Exists(u.DefaultEnv) {
			if err := h.Users.ChangeDefaultEnv(u.Username, u.DefaultEnv); err != nil {
				adminErrorResponse(w, "error changing default environment", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if u.NewPassword != "" {
			if err := h.Users.ChangePassword(u.Username, u.NewPassword); err != nil {
				adminErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user updated successfully")
	case "remove":
		if u.Username == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to remove current user %s", u.Username))
			h.Inc(metricAdminErr)
			return
		}
		if h.Users.Exists(u.Username) {
			if err := h.Users.Delete(u.Username); err != nil {
				adminErrorResponse(w, "error removing user", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "user removed successfully")
	case "admin":
		if u.Username == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to de-admin current user %s", u.Username))
			h.Inc(metricAdminErr)
			return
		}
		if h.Users.Exists(u.Username) {
			if err := h.Users.ChangeAdmin(u.Username, u.Admin); err != nil {
				adminErrorResponse(w, "error changing admin", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
			if u.Admin {
				_, err := h.Envs.Names()
				if err != nil {
					adminErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				/*
					perms := h.Users.GenPermissions(namesEnvs, users.AdminLevel)
					if err := h.Users.ChangePermissions(u.Username, perms); err != nil {
						adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
						h.Inc(metricAdminErr)
						return
					}
				*/
				token, exp, err := h.Users.CreateToken(u.Username)
				if err != nil {
					adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
				if err := h.Users.UpdateToken(u.Username, token, exp); err != nil {
					adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
			}
			adminOKResponse(w, "admin changed successfully")
		}
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
	h.Inc(metricAdminOK)
}

// TagsPOSTHandler for POST request for /tags
func (h *HandlersAdmin) TagsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var t TagsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch t.Action {
	case "add":
		// FIXME password complexity?
		if h.Tags.Exists(t.Name) {
			adminErrorResponse(w, "error adding tag", http.StatusInternalServerError, fmt.Errorf("tag %s already exists", t.Name))
			h.Inc(metricAdminErr)
			return
		}
		// Prepare user to create
		if err := h.Tags.NewTag(t.Name, t.Description, t.Color, t.Icon, ctx[sessions.CtxUser]); err != nil {
			adminErrorResponse(w, "error with new tag", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		adminOKResponse(w, "tag added successfully")
	case "edit":
		if t.Description != "" {
			if err := h.Tags.ChangeDescription(t.Name, t.Description); err != nil {
				adminErrorResponse(w, "error changing description", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if t.Icon != "" {
			if err := h.Tags.ChangeIcon(t.Name, t.Icon); err != nil {
				adminErrorResponse(w, "error changing icon", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if t.Color != "" {
			if err := h.Tags.ChangeColor(t.Name, t.Color); err != nil {
				adminErrorResponse(w, "error changing color", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "tag updated successfully")
	case "remove":
		if t.Name == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to remove tag %s", t.Name))
			h.Inc(metricAdminErr)
			return
		}
		if h.Tags.Exists(t.Name) {
			if err := h.Tags.Delete(t.Name); err != nil {
				adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "tag removed successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Tags response sent")
	}
	h.Inc(metricAdminOK)
}

// TagNodesPOSTHandler for POST request for /tags/nodes
func (h *HandlersAdmin) TagNodesPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	var t TagNodesRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	var toBeProcessed []nodes.OsqueryNode
	for _, u := range t.UUIDs {
		n, err := h.Nodes.GetByUUID(u)
		if err != nil {
			adminErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		toBeProcessed = append(toBeProcessed, n)
	}
	// Processing the list of tags to remove
	for _, _t := range t.TagsRemove {
		if !h.Tags.Exists(_t) {
			adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, fmt.Errorf("tag %s does not exists", _t))
			h.Inc(metricAdminErr)
			return
		}
		// Untag all nodes
		for _, n := range toBeProcessed {
			if err := h.Tags.UntagNode(_t, n); err != nil {
				adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
	}
	// Processing the list of tags to add and all nodes to tag
	for _, n := range toBeProcessed {
		if err := h.Tags.TagNodeMulti(t.TagsAdd, n, ctx[sessions.CtxUser], false); err != nil {
			adminErrorResponse(w, "error with tag", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Tags response sent")
	}
	adminOKResponse(w, "tags processed successfully")
	h.Inc(metricAdminOK)
}

// PermissionsPOSTHandler for POST request for /users/permissions
func (h *HandlersAdmin) PermissionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract username and verify
	usernameVar, ok := vars["username"]
	if !ok || !h.Users.Exists(usernameVar) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	var p PermissionsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], p.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// TODO verify environments and this should reflect the updated struct for permissions
	perms := users.EnvAccess{
		User:  true,
		Query: p.Query,
		Carve: p.Carve,
		Admin: true,
	}
	// TODO empty environment until the correct request is sent
	if err := h.Users.ChangeAccess(usernameVar, "", perms); err != nil {
		adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users response sent")
	}
	adminOKResponse(w, "OK")
	h.Inc(metricAdminOK)
}

// EnrollPOSTHandler for POST requests enroll data
func (h *HandlersAdmin) EnrollPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error getting environment: %v", err)
		return
	}
	var e EnrollRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		h.Inc(metricAdminErr)
		return
	}
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	if e.CertificateB64 == "" {
		adminErrorResponse(w, "empty certificate", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	certificate, err := base64.StdEncoding.DecodeString(e.CertificateB64)
	if err != nil {
		adminErrorResponse(w, "error decoding certificate", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	if err := h.Envs.UpdateCertificate(env.UUID, string(certificate)); err != nil {
		adminErrorResponse(w, "error saving certificate", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Configuration response sent")
	}
	adminOKResponse(w, "enroll data saved")
	h.Inc(metricAdminOK)
}

// EditProfilePOSTHandler for POST requests to edit profile
func (h *HandlersAdmin) EditProfilePOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], u.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	// User must be the same as logged in
	if u.Username != ctx[sessions.CtxUser] {
		adminErrorResponse(w, "invalid user profile", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch u.Action {
	case "change_password":
		// Verify previous password
		if u.OldPassword != "" {
			access, user := h.Users.CheckLoginCredentials(u.Username, u.OldPassword)
			if !access {
				adminErrorResponse(w, "error changing password", http.StatusInternalServerError, fmt.Errorf("bad old password"))
				h.Inc(metricAdminErr)
				return
			}
			// Update password with the new one
			if access && u.NewPassword != "" {
				if err := h.Users.ChangePassword(user.Username, u.NewPassword); err != nil {
					adminErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
					h.Inc(metricAdminErr)
					return
				}
			}
			adminOKResponse(w, "password changed successfully")
		}
	case "edit":
		// Retrieve user
		user, err := h.Users.Get(u.Username)
		if err != nil {
			adminErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
			h.Inc(metricAdminErr)
			return
		}
		if u.Fullname != user.Fullname {
			if err := h.Users.ChangeFullname(user.Username, u.Fullname); err != nil {
				adminErrorResponse(w, "error changing fullname", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if u.Email != user.Email {
			if err := h.Users.ChangeEmail(user.Username, u.Email); err != nil {
				adminErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		if u.DefaultEnv != user.DefaultEnv && h.Envs.Exists(u.DefaultEnv) {
			if err := h.Users.ChangeDefaultEnv(user.Username, u.DefaultEnv); err != nil {
				adminErrorResponse(w, "error changing default environment", http.StatusInternalServerError, err)
				h.Inc(metricAdminErr)
				return
			}
		}
		adminOKResponse(w, "profiled updated successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Edit profile response sent")
	}
	h.Inc(metricAdminOK)
}

// SavedQueriesPOSTHandler for POST requests to save queries
func (h *HandlersAdmin) SavedQueriesPOSTHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	var s SavedQueryRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Parse request JSON body
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Decoding POST body")
	}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], s.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		h.Inc(metricAdminErr)
		return
	}
	switch s.Action {
	case "create":
		adminOKResponse(w, "query created successfully")
	case "edit":
		adminOKResponse(w, "query saved successfully")
	}
	// Serialize and send response
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Saved query response sent")
	}
	h.Inc(metricAdminOK)
}
