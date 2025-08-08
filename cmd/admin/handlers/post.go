package handlers

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// LoginPOSTHandler for login page for POST requests
func (h *HandlersAdmin) LoginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	// Never show the body in the login request
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	var l LoginRequest
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check credentials
	access, user := h.Users.CheckLoginCredentials(l.Username, l.Password)
	if !access {
		adminErrorResponse(w, "invalid credentials", http.StatusForbidden, nil)
		return
	}
	_, err := h.Sessions.Save(r, w, user)
	if err != nil {
		adminErrorResponse(w, "session error", http.StatusForbidden, err)
		return
	}
	// Serialize and send response
	log.Debug().Msg("Login response sent")
	adminOKResponse(w, "/dashboard")
}

// LogoutPOSTHandler for POST requests to logout
func (h *HandlersAdmin) LogoutPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var l LogoutRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], l.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// Destroy existing session
	if err := h.Sessions.Destroy(r); err != nil {
		adminErrorResponse(w, "error destroying session", http.StatusInternalServerError, err)
		return
	}
	// Serialize and send response
	log.Debug().Msg("Logout response sent")
	adminOKResponse(w, "OK")
}

// QueryRunPOSTHandler for POST requests to run queries
func (h *HandlersAdmin) QueryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions for query
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	var q DistributedQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// FIXME check validity of query
	// Query can not be empty
	if q.Query == "" {
		adminErrorResponse(w, "query can not be empty", http.StatusInternalServerError, nil)
		return
	}
	// FIXME check if query is carve and user has permissions to carve
	// Prepare and create new query
	expTime := queries.QueryExpiration(q.ExpHours)
	if q.ExpHours == 0 {
		expTime = time.Time{}
	}
	newQuery := newQueryReady(ctx[sessions.CtxUser], q.Query, expTime, env.ID)
	if err := h.Queries.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	// Get the query id
	newQuery, err = h.Queries.Get(newQuery.Name, env.ID)
	if err != nil {
		adminErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	// List all the nodes that match the query
	var expected []uint
	targetNodesID := []uint{}
	// TODO: Refactor this to use osctrl-api instead of direct DB queries
	// Create environment target
	if len(q.Environments) > 0 {
		expected = []uint{}
		for _, e := range q.Environments {
			if (e != "") && h.Envs.Exists(e) {
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
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
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
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
					log.Err(err).Msgf("error getting node %s and failed to create node query for it", u)
					continue
				}
				expected = append(expected, node.ID)
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Create hostnames target
	if len(q.Hosts) > 0 {
		expected = []uint{}
		for _, _h := range q.Hosts {
			if _h != "" {
				node, err := h.Nodes.GetByIdentifier(_h)
				if err != nil {
					log.Err(err).Msgf("error getting node %s and failed to create node query for it", _h)
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
			adminErrorResponse(w, "error creating node queries", http.StatusInternalServerError, err)
			return
		}
	}
	// Update value for expected
	if err := h.Queries.SetExpected(newQuery.Name, len(targetNodesID), env.ID); err != nil {
		adminErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		return
	}
	// Save query if requested and if the name is not empty
	if q.Save && q.Name != "" {
		if err := h.Queries.CreateSaved(q.Name, q.Query, ctx[sessions.CtxUser], env.ID); err != nil {
			adminErrorResponse(w, "error saving query", http.StatusInternalServerError, err)
			return
		}
	}
	// Serialize and send response
	log.Debug().Msg("Query run response sent")
	adminOKResponse(w, "OK")
}

// CarvesRunPOSTHandler for POST requests to run file carves
func (h *HandlersAdmin) CarvesRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	var c DistributedCarveRequest
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// FIXME check validity of query
	// Path can not be empty
	if c.Path == "" {
		adminErrorResponse(w, "path can not be empty", http.StatusInternalServerError, nil)
		return
	}
	query := generateCarveQuery(c.Path, false)
	// Prepare and create new carve
	carveName := generateCarveName()
	// Set query expiration
	expTime := queries.QueryExpiration(c.ExpHours)
	if c.ExpHours == 0 {
		expTime = time.Time{}
	}
	newQuery := queries.DistributedQuery{
		Query:         query,
		Name:          carveName,
		Creator:       ctx[sessions.CtxUser],
		Expected:      0,
		Executions:    0,
		Active:        true,
		Completed:     false,
		Deleted:       false,
		Expired:       false,
		Expiration:    expTime,
		Type:          queries.CarveQueryType,
		Path:          c.Path,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(newQuery); err != nil {
		adminErrorResponse(w, "error creating carve", http.StatusInternalServerError, err)
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
					return
				}
				nodes, err := h.Nodes.GetByEnv(e, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					adminErrorResponse(w, "error getting nodes by environment", http.StatusInternalServerError, err)
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
					return
				}
				nodes, err := h.Nodes.GetByPlatform(p, "active", h.Settings.InactiveHours(settings.NoEnvironmentID))
				if err != nil {
					adminErrorResponse(w, "error getting nodes by platform", http.StatusInternalServerError, err)
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
		return
	}
	// Serialize and send response
	log.Debug().Msg("Carve run response sent")
	adminOKResponse(w, "OK")
}

// QueryActionsPOSTHandler for POST requests to queries
func (h *HandlersAdmin) QueryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions for query
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	var q DistributedQueryActionRequest
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.Names {
			if err := h.Queries.Delete(n, env.ID); err != nil {
				adminErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "queries delete successfully")
	case "complete":
		for _, n := range q.Names {
			if err := h.Queries.Complete(n, env.ID); err != nil {
				adminErrorResponse(w, "error completing query", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "queries completed successfully")
	case "activate":
		for _, n := range q.Names {
			if err := h.Queries.Activate(n, env.ID); err != nil {
				adminErrorResponse(w, "error activating query", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "queries activated successfully")
	case "saved_delete":
		for _, n := range q.Names {
			if err := h.Queries.DeleteSaved(n, ctx[sessions.CtxUser], env.ID); err != nil {
				adminErrorResponse(w, "error deleting query", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "queries delete successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Query run response sent")
}

// CarvesActionsPOSTHandler - Handler for POST requests to carves
func (h *HandlersAdmin) CarvesActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var q DistributedCarvesActionRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], q.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch q.Action {
	case "delete":
		for _, n := range q.IDs {
			if err := h.Carves.Delete(n); err != nil {
				adminErrorResponse(w, "error deleting carve", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "carves delete successfully")
	case "test":
		log.Debug().Msg("testing action")
		adminOKResponse(w, "test successful")
	}
	// Serialize and send response
	log.Debug().Msg("Carves action response sent")
}

// ConfPOSTHandler for POST requests for saving configuration
func (h *HandlersAdmin) ConfPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment")
		return
	}
	var c ConfigurationRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	if c.ConfigurationB64 != "" {
		// Base64 decode received configuration
		// TODO verify configuration
		configuration, err := base64.StdEncoding.DecodeString(c.ConfigurationB64)
		if err != nil {
			adminErrorResponse(w, "error decoding configuration", http.StatusInternalServerError, err)
			return
		}
		// Parse configuration
		cnf, err := h.Envs.GenStructConf(configuration)
		if err != nil {
			adminErrorResponse(w, "error parsing configuration", http.StatusInternalServerError, err)
			return
		}
		// Update configuration
		if err := h.Envs.UpdateConfiguration(env.UUID, cnf); err != nil {
			adminErrorResponse(w, "error saving configuration", http.StatusInternalServerError, err)
			return
		}
		// Update all configuration parts
		if err := h.Envs.UpdateConfigurationParts(env.UUID, cnf); err != nil {
			adminErrorResponse(w, "error saving configuration parts", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("Configuration response sent")
		adminOKResponse(w, "configuration saved successfully")
		return
	}
	if c.OptionsB64 != "" {
		// Base64 decode received options
		// TODO verify options
		options, err := base64.StdEncoding.DecodeString(c.OptionsB64)
		if err != nil {
			adminErrorResponse(w, "error decoding options", http.StatusInternalServerError, err)
			return
		}
		// Update options
		if err := h.Envs.UpdateOptions(env.UUID, string(options)); err != nil {
			adminErrorResponse(w, "error saving options", http.StatusInternalServerError, err)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("Options response sent")
		adminOKResponse(w, "options saved successfully")
		return
	}
	if c.ScheduleB64 != "" {
		// TODO verify schedule
		// Decode received configuration
		schedule, err := base64.StdEncoding.DecodeString(c.ScheduleB64)
		if err != nil {
			adminErrorResponse(w, "error decoding schedule", http.StatusInternalServerError, err)
			return
		}
		// Update schedule
		if err := h.Envs.UpdateSchedule(env.UUID, string(schedule)); err != nil {
			adminErrorResponse(w, "error saving schedule", http.StatusInternalServerError, err)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("Schedule response sent")
		adminOKResponse(w, "schedule saved successfully")
		return
	}
	if c.PacksB64 != "" {
		// TODO verify packs
		// Base64 decode received packs
		packs, err := base64.StdEncoding.DecodeString(c.PacksB64)
		if err != nil {
			adminErrorResponse(w, "error decoding packs", http.StatusInternalServerError, err)
			return
		}
		// Update packs
		if err := h.Envs.UpdatePacks(env.UUID, string(packs)); err != nil {
			adminErrorResponse(w, "error saving packs", http.StatusInternalServerError, err)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("Packs response sent")
		adminOKResponse(w, "packs saved successfully")
		return
	}
	if c.DecoratorsB64 != "" {
		// Base64 decode received options
		// TODO verify decorators
		decorators, err := base64.StdEncoding.DecodeString(c.DecoratorsB64)
		if err != nil {
			adminErrorResponse(w, "error decoding decorators", http.StatusInternalServerError, err)
			return
		}
		// Update decorators
		if err := h.Envs.UpdateDecorators(env.UUID, string(decorators)); err != nil {
			adminErrorResponse(w, "error saving decorators", http.StatusInternalServerError, err)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("Decorators response sent")
		adminOKResponse(w, "decorators saved successfully")
		return
	}
	if c.ATCB64 != "" {
		// TODO verify ATC
		// Base64 decode received ATC
		schedule, err := base64.StdEncoding.DecodeString(c.ATCB64)
		if err != nil {
			adminErrorResponse(w, "error decoding ATC", http.StatusInternalServerError, err)
			return
		}
		// Update ATC
		if err := h.Envs.UpdateATC(env.UUID, string(schedule)); err != nil {
			adminErrorResponse(w, "error saving ATC", http.StatusInternalServerError, err)
			return
		}
		// Update full configuration
		if err := h.Envs.RefreshConfiguration(env.UUID); err != nil {
			adminErrorResponse(w, "error updating configuration", http.StatusInternalServerError, err)
			return
		}
		// Send response
		log.Debug().Msg("ATC response sent")
		adminOKResponse(w, "ATC saved successfully")
		return
	}
	// If we are here, means that the request received was empty
	responseMessage := "empty configuration"
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, AdminResponse{Message: responseMessage})
	log.Debug().Msgf("%s", responseMessage)
}

// IntervalsPOSTHandler for POST requests for saving intervals
func (h *HandlersAdmin) IntervalsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment and verify
	envVar := r.PathValue("env")
	if envVar == "" || !h.Envs.Exists(envVar) {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	// TODO do the exist and get in one step
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	var c IntervalsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	if err := h.Envs.UpdateIntervals(env.Name, c.ConfigInterval, c.LogInterval, c.QueryInterval); err != nil {
		adminErrorResponse(w, "error updating intervals", http.StatusInternalServerError, err)
		return
	}
	// After updating interval, you need to re-generate flags
	flags, err := h.Envs.GenerateFlagsEnv(envVar, "", "")
	if err != nil {
		adminErrorResponse(w, "error re-generating flags", http.StatusInternalServerError, err)
		return
	}
	// Update flags in the newly created environment
	if err := h.Envs.UpdateFlags(envVar, flags); err != nil {
		adminErrorResponse(w, "error updating flags", http.StatusInternalServerError, err)
		return
	}
	// Serialize and send response
	log.Debug().Msg("Intervals response sent")
	adminOKResponse(w, "intervals saved successfully")
}

// ExpirationPOSTHandler for POST requests for expiring enroll links
func (h *HandlersAdmin) ExpirationPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment")
		return
	}
	var e ExpirationRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch e.Type {
	case settings.ScriptEnroll:
		switch e.Action {
		case "expire":
			if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error expiring enroll", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case "extend":
			if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error extending enroll", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link extended successfully")
		case "rotate":
			if err := h.Envs.RotateEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error rotating enroll", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link rotated successfully")
		case "notexpire":
			if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
				adminErrorResponse(w, "error not expiring enroll", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link set to not expire successfully")
		}
	case settings.ScriptRemove:
		switch e.Action {
		case settings.ActionExpire:
			if err := h.Envs.ExpireRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link expired successfully")
		case settings.ActionExtend:
			if err := h.Envs.ExtendRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link extended successfully")
		case settings.ActionRotate:
			if err := h.Envs.RotateRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link rotated successfully")
		case settings.ActionNotexpire:
			if err := h.Envs.NotExpireRemove(env.UUID); err != nil {
				adminErrorResponse(w, "error not expiring remove", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "link set to not expire successfully")
		}
	}
	// Serialize and send response
	log.Debug().Msg("Expiration response sent")
}

// NodeActionsPOSTHandler for POST requests for multi node action
func (h *HandlersAdmin) NodeActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var m NodeMultiActionRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], m.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	if m.Action == "delete" {
		okCount := 0
		errCount := 0
		for _, u := range m.UUIDs {
			if err := h.Nodes.ArchiveDeleteByUUID(u); err != nil {
				errCount++
				log.Err(err).Msgf("error deleting node %s", u)
			} else {
				okCount++
			}
		}
		if errCount == 0 {
			adminOKResponse(w, fmt.Sprintf("%d Node(s) have been deleted successfully", okCount))
		} else {
			adminErrorResponse(w, fmt.Sprintf("Error deleting %d node(s)", errCount), http.StatusInternalServerError, nil)
			return
		}
	}
	// Serialize and send response
	log.Debug().Msg("Multi-node action response sent")
}

// EnvsPOSTHandler for POST request for /environments
func (h *HandlersAdmin) EnvsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var c EnvironmentsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], c.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch c.Action {
	case "create":
		// FIXME verify fields
		if !h.Envs.Exists(c.Name) && c.Name != "" {
			env := h.Envs.Empty(c.Name, c.Hostname)
			env.Icon = c.Icon
			env.Type = c.Type
			// Empty configuration
			env.Configuration = h.Envs.GenEmptyConfiguration(true)
			// Generate flags
			flags, err := h.Envs.GenerateFlags(env, "", "")
			if err != nil {
				adminErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
				return
			}
			env.Flags = flags
			if err := h.Envs.Create(&env); err != nil {
				adminErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
				return
			}
			// Generate full permissions for the user creating the environment
			access := h.Users.GenEnvUserAccess([]string{env.UUID}, true, true, true, true)
			perms := h.Users.GenPermissions(ctx[sessions.CtxUser], "osctrl-admin", access)
			if err := h.Users.CreatePermissions(perms); err != nil {
				adminErrorResponse(w, "error generating permissions", http.StatusInternalServerError, err)
				return
			}
			// Create a tag for this new environment
			if err := h.Tags.NewTag(
				env.Name,
				"Tag for environment "+env.Name,
				"",
				env.Icon,
				ctx[sessions.CtxUser],
				env.ID,
				false,
				tags.TagTypeEnv); err != nil {
				adminErrorResponse(w, "error generating tag", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "environment created successfully")
		} else {
			adminOKResponse(w, "invalid environment")
			return
		}
	case "delete":
		if h.Envs.Exists(c.Name) {
			if err := h.Envs.Delete(c.Name); err != nil {
				adminErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "environment deleted successfully")
	case "edit":
		if h.Envs.Exists(c.UUID) {
			if err := h.Envs.UpdateHostname(c.UUID, c.Hostname); err != nil {
				adminErrorResponse(w, "error updating hostname", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "debug changed successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Environments response sent")
}

// SettingsPOSTHandler for POST request for /settings
func (h *HandlersAdmin) SettingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract service
	serviceVar := r.PathValue("service")
	if serviceVar == "" {
		adminErrorResponse(w, "error getting service", http.StatusInternalServerError, nil)
		return
	}
	// Verify service
	if !checkTargetService(serviceVar) {
		adminErrorResponse(w, fmt.Sprintf("unknown service (%s)", serviceVar), http.StatusForbidden, nil)
		return
	}
	var s SettingsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], s.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch s.Action {
	case "add":
		if !h.Settings.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = h.Settings.NewBooleanValue(serviceVar, s.Name, utils.StringToBoolean(s.Value), settings.NoEnvironmentID)
		case settings.TypeInteger:
			err = h.Settings.NewIntegerValue(serviceVar, s.Name, utils.StringToInteger(s.Value), settings.NoEnvironmentID)
		case settings.TypeString:
			err = h.Settings.NewStringValue(serviceVar, s.Name, s.Value, settings.NoEnvironmentID)
		}
		if err != nil {
			adminErrorResponse(w, "error adding setting", http.StatusInternalServerError, err)
			return
		}
		adminOKResponse(w, "setting added successfully")
	case "change":
		if !h.Settings.VerifyType(s.Type) {
			adminErrorResponse(w, "invalid type", http.StatusInternalServerError, nil)
			return
		}
		var err error
		switch s.Type {
		case settings.TypeBoolean:
			err = h.Settings.SetBoolean(s.Boolean, serviceVar, s.Name, settings.NoEnvironmentID)
		case settings.TypeInteger:
			err = h.Settings.SetInteger(utils.StringToInteger(s.Value), serviceVar, s.Name, settings.NoEnvironmentID)
		case settings.TypeString:
			err = h.Settings.SetString(s.Value, serviceVar, s.Name, false, settings.NoEnvironmentID)
		}
		if err != nil {
			adminErrorResponse(w, "error changing setting", http.StatusInternalServerError, err)
			return
		}
		adminOKResponse(w, "setting changed successfully")
	case "delete":
		if err := h.Settings.DeleteValue(serviceVar, s.Name, settings.NoEnvironmentID); err != nil {
			adminErrorResponse(w, "error deleting setting", http.StatusInternalServerError, err)
			return
		}
		adminOKResponse(w, "setting deleted successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Settings response sent")
}

// UsersPOSTHandler for POST request for /users
func (h *HandlersAdmin) UsersPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], u.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch u.Action {
	case "add":
		// FIXME password complexity?
		if h.Users.Exists(u.Username) {
			adminErrorResponse(w, "error adding user", http.StatusInternalServerError, fmt.Errorf("user %s already exists", u.Username))
			return
		}
		// Prepare user to create
		newUser, err := h.Users.New(u.Username, u.NewPassword, u.Email, u.Fullname, u.Admin, u.Service)
		if err != nil {
			adminErrorResponse(w, "error with new user", http.StatusInternalServerError, err)
			return
		}
		// Create new user
		if err = h.Users.Create(newUser); err != nil {
			adminErrorResponse(w, "error creating user", http.StatusInternalServerError, err)
			return
		}
		// TODO verify environments
		access := h.Users.GenEnvUserAccess(u.Environments, true, (u.Admin), (u.Admin), (u.Admin))
		perms := h.Users.GenPermissions(u.Username, ctx[sessions.CtxUser], access)
		if err := h.Users.CreatePermissions(perms); err != nil {
			adminErrorResponse(w, "error creating permissions", http.StatusInternalServerError, err)
			return
		}
		if u.Token {
			token, exp, err := h.Users.CreateToken(newUser.Username, h.AdminConfig.Host, h.Users.JWTConfig.HoursToExpire)
			if err != nil {
				adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
				return
			}
			if err = h.Users.UpdateToken(newUser.Username, token, exp); err != nil {
				adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "user added successfully")
	case "edit":
		if u.Fullname != "" {
			if err := h.Users.ChangeFullname(u.Username, u.Fullname); err != nil {
				adminErrorResponse(w, "error changing fullname", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Email != "" {
			if err := h.Users.ChangeEmail(u.Username, u.Email); err != nil {
				adminErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				return
			}
		}
		if u.NewPassword != "" {
			if err := h.Users.ChangePassword(u.Username, u.NewPassword); err != nil {
				adminErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "user updated successfully")
	case "remove":
		if u.Username == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to remove current user %s", u.Username))
			return
		}
		exist, user := h.Users.ExistsGet(u.Username)
		if exist {
			if err := h.Users.Delete(user.Username); err != nil {
				adminErrorResponse(w, "error removing user", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "user removed successfully")
	case "admin":
		if u.Username == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to de-admin current user %s", u.Username))
			return
		}
		if h.Users.Exists(u.Username) {
			if err := h.Users.ChangeAdmin(u.Username, u.Admin); err != nil {
				adminErrorResponse(w, "error changing admin", http.StatusInternalServerError, err)
				return
			}
			if u.Admin {
				_, err := h.Envs.Names()
				if err != nil {
					adminErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
					return
				}
				/*
					perms := h.Users.GenPermissions(namesEnvs, users.AdminLevel)
					if err := h.Users.ChangePermissions(u.Username, perms); err != nil {
						adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
												return
					}
				*/
				token, exp, err := h.Users.CreateToken(u.Username, h.AdminConfig.Host, h.Users.JWTConfig.HoursToExpire)
				if err != nil {
					adminErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
					return
				}
				if err := h.Users.UpdateToken(u.Username, token, exp); err != nil {
					adminErrorResponse(w, "error saving token", http.StatusInternalServerError, err)
					return
				}
			}
			adminOKResponse(w, "admin changed successfully")
		}
	case "service":
		if u.Username == ctx[sessions.CtxUser] {
			adminErrorResponse(w, "not a good idea", http.StatusInternalServerError, fmt.Errorf("attempt to service current user %s", u.Username))
			return
		}
		if h.Users.Exists(u.Username) {
			if err := h.Users.ChangeService(u.Username, u.Service); err != nil {
				adminErrorResponse(w, "error changing service", http.StatusInternalServerError, err)
				return
			}
			adminOKResponse(w, "service changed successfully")
		}
	}
	// Serialize and send response
	log.Debug().Msg("Users response sent")
}

// TagsPOSTHandler for POST request for /tags
func (h *HandlersAdmin) TagsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var t TagsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// Retrieve environment
	env, err := h.Envs.Get(t.Environment)
	if err != nil {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	switch t.Action {
	case tags.ActionAdd:
		if h.Tags.ExistsByEnv(t.Name, env.ID) {
			adminErrorResponse(w, "error adding tag", http.StatusInternalServerError, fmt.Errorf("tag %s already exists", t.Name))
			return
		}
		if err := h.Tags.NewTag(t.Name, t.Description, t.Color, t.Icon, ctx[sessions.CtxUser], env.ID, false, t.TagType); err != nil {
			adminErrorResponse(w, "error with new tag", http.StatusInternalServerError, err)
			return
		}
		adminOKResponse(w, "tag added successfully")
	case tags.ActionEdit:
		tag, err := h.Tags.Get(t.Name, env.ID)
		if err != nil {
			adminErrorResponse(w, "error getting tag", http.StatusInternalServerError, err)
			return
		}
		if t.Description != "" && t.Description != tag.Description {
			if err := h.Tags.ChangeDescription(&tag, t.Description); err != nil {
				adminErrorResponse(w, "error changing description", http.StatusInternalServerError, err)
				return
			}
		}
		if t.Icon != "" && t.Icon != tag.Icon {
			if err := h.Tags.ChangeIcon(&tag, t.Icon); err != nil {
				adminErrorResponse(w, "error changing icon", http.StatusInternalServerError, err)
				return
			}
		}
		if t.Color != "" && t.Color != tag.Color {
			if err := h.Tags.ChangeColor(&tag, t.Color); err != nil {
				adminErrorResponse(w, "error changing color", http.StatusInternalServerError, err)
				return
			}
		}
		if t.TagType != tag.TagType {
			if err := h.Tags.ChangeTagType(&tag, t.TagType); err != nil {
				adminErrorResponse(w, "error changing tag type", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "tag updated successfully")
	case tags.ActionRemove:
		if err := h.Tags.DeleteGet(t.Name, env.ID); err != nil {
			adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
			return
		}
		adminOKResponse(w, "tag removed successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Tags response sent")
}

// TagNodesPOSTHandler for POST request for /tags/nodes
func (h *HandlersAdmin) TagNodesPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var t TagNodesRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], t.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	var toBeProcessed []nodes.OsqueryNode
	for _, u := range t.UUIDs {
		n, err := h.Nodes.GetByUUID(u)
		if err != nil {
			adminErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
			return
		}
		toBeProcessed = append(toBeProcessed, n)
	}
	// Processing the list of tags to remove
	for _, _t := range t.TagsRemove {
		if !h.Tags.Exists(_t) {
			adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, fmt.Errorf("tag %s does not exists", _t))
			return
		}
		// Untag all nodes
		for _, n := range toBeProcessed {
			if err := h.Tags.UntagNode(_t, n); err != nil {
				adminErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
				return
			}
		}
	}
	// Processing the list of tags to add and all nodes to tag
	for _, n := range toBeProcessed {
		if err := h.Tags.TagNodeMulti(t.TagsAdd, n, ctx[sessions.CtxUser], false); err != nil {
			adminErrorResponse(w, "error with tag", http.StatusInternalServerError, err)
			return
		}
	}
	// Serialize and send response
	log.Debug().Msg("Tags response sent")
	adminOKResponse(w, "tags processed successfully")
}

// PermissionsPOSTHandler for POST request for /users/permissions
func (h *HandlersAdmin) PermissionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract username and verify
	usernameVar := r.PathValue("username")
	if usernameVar == "" || !h.Users.Exists(usernameVar) {
		adminErrorResponse(w, "error getting username", http.StatusInternalServerError, nil)
		return
	}
	var p PermissionsRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Retrieve environment
	env, err := h.Envs.Get(p.Environment)
	if err != nil {
		adminErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], p.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// TODO verify environments and this should reflect the updated struct for permissions
	perms := users.GenEnvAccess(p.Admin, p.Carve, p.Query, p.Read)
	// Check if user already have access to this environment
	existing, err := h.Users.GetEnvAccess(usernameVar, env.UUID)
	if err != nil && strings.Contains(err.Error(), "record not found") {
		envAccess := h.Users.GenUserAccess(env, perms)
		generatedPerms := h.Users.GenPermissions(usernameVar, ctx[sessions.CtxUser], envAccess)
		if err := h.Users.CreatePermissions(generatedPerms); err != nil {
			adminErrorResponse(w, "error creating permissions", http.StatusInternalServerError, err)
			return
		}
	}
	if existing != (users.EnvAccess{}) && !users.SameAccess(perms, existing) {
		if err := h.Users.ChangeAccess(usernameVar, env.UUID, perms); err != nil {
			adminErrorResponse(w, "error changing permissions", http.StatusInternalServerError, err)
			return
		}
	}
	// Serialize and send response
	log.Debug().Msg("Users response sent")
	adminOKResponse(w, "permissions updated successfully")
}

// EnrollPOSTHandler for POST requests enroll data
func (h *HandlersAdmin) EnrollPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment")
		return
	}
	var e EnrollRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, env.UUID) {
		adminErrorResponse(w, fmt.Sprintf("%s has insuficient permissions", ctx[sessions.CtxUser]), http.StatusForbidden, nil)
		return
	}
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], e.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch e.Action {
	case "enroll_certificate":
		if e.CertificateB64 == "" {
			adminErrorResponse(w, "empty certificate", http.StatusInternalServerError, nil)
			return
		}
		certificate, err := base64.StdEncoding.DecodeString(e.CertificateB64)
		if err != nil {
			adminErrorResponse(w, "error decoding certificate", http.StatusInternalServerError, err)
			return
		}
		if err := h.Envs.UpdateCertificate(env.UUID, string(certificate)); err != nil {
			adminErrorResponse(w, "error saving certificate", http.StatusInternalServerError, err)
			return
		}
	case "package_deb":
		if e.PackageURL != env.DebPackage {
			if e.PackageURL == "" {
				adminErrorResponse(w, "empty package URL", http.StatusInternalServerError, nil)
				return
			}
			if err := h.Envs.UpdateDebPackage(env.UUID, e.PackageURL); err != nil {
				adminErrorResponse(w, "error saving package URL", http.StatusInternalServerError, err)
				return
			}
		}
	case "package_rpm":
		if e.PackageURL != env.RpmPackage {
			if e.PackageURL == "" {
				adminErrorResponse(w, "empty package URL", http.StatusInternalServerError, nil)
				return
			}
			if err := h.Envs.UpdateRpmPackage(env.UUID, e.PackageURL); err != nil {
				adminErrorResponse(w, "error saving package URL", http.StatusInternalServerError, err)
				return
			}
		}
	case "package_pkg":
		if e.PackageURL != env.PkgPackage {
			if e.PackageURL == "" {
				adminErrorResponse(w, "empty package URL", http.StatusInternalServerError, nil)
				return
			}
			if err := h.Envs.UpdatePkgPackage(env.UUID, e.PackageURL); err != nil {
				adminErrorResponse(w, "error saving package URL", http.StatusInternalServerError, err)
				return
			}
		}
	case "package_msi":
		if e.PackageURL != env.MsiPackage {
			if e.PackageURL == "" {
				adminErrorResponse(w, "empty package URL", http.StatusInternalServerError, nil)
				return
			}
			if err := h.Envs.UpdateMsiPackage(env.UUID, e.PackageURL); err != nil {
				adminErrorResponse(w, "error saving package URL", http.StatusInternalServerError, err)
				return
			}
		}
	}
	// Serialize and send response
	log.Debug().Msg("Configuration response sent")
	adminOKResponse(w, "enroll data saved")
}

// EditProfilePOSTHandler for POST requests to edit profile
func (h *HandlersAdmin) EditProfilePOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var u UsersRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], u.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	// User must be the same as logged in
	if u.Username != ctx[sessions.CtxUser] {
		adminErrorResponse(w, "invalid user profile", http.StatusInternalServerError, nil)
		return
	}
	switch u.Action {
	case "change_password":
		// Verify previous password
		if u.OldPassword != "" {
			access, user := h.Users.CheckLoginCredentials(u.Username, u.OldPassword)
			if !access {
				adminErrorResponse(w, "error changing password", http.StatusInternalServerError, fmt.Errorf("bad old password"))
				return
			}
			// Update password with the new one
			if access && u.NewPassword != "" {
				if err := h.Users.ChangePassword(user.Username, u.NewPassword); err != nil {
					adminErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
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
			return
		}
		if u.Fullname != user.Fullname {
			if err := h.Users.ChangeFullname(user.Username, u.Fullname); err != nil {
				adminErrorResponse(w, "error changing fullname", http.StatusInternalServerError, err)
				return
			}
		}
		if u.Email != user.Email {
			if err := h.Users.ChangeEmail(user.Username, u.Email); err != nil {
				adminErrorResponse(w, "error changing email", http.StatusInternalServerError, err)
				return
			}
		}
		adminOKResponse(w, "profiled updated successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Edit profile response sent")
}

// SavedQueriesPOSTHandler for POST requests to save queries
func (h *HandlersAdmin) SavedQueriesPOSTHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.Enabled {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	var s SavedQueryRequest
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Parse request JSON body
	log.Debug().Msg("Decoding POST body")
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		adminErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	// Check CSRF Token
	if !sessions.CheckCSRFToken(ctx[sessions.CtxCSRF], s.CSRFToken) {
		adminErrorResponse(w, "invalid CSRF token", http.StatusInternalServerError, nil)
		return
	}
	switch s.Action {
	case "create":
		adminOKResponse(w, "query created successfully")
	case "edit":
		adminOKResponse(w, "query saved successfully")
	}
	// Serialize and send response
	log.Debug().Msg("Saved query response sent")
}
