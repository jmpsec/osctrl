package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// NodeHandler - GET Handler for single JSON nodes
// @Summary Get node
// @Description Returns a single enrolled node in an environment, including admin-only detail fields.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param node path string true "Node UUID, hostname, or local name"
// @Success 200 {object} types.NodeView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{node} [get]
func (h *HandlersApi) NodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	// Extract host identifier for node
	nodeVar := r.PathValue("node")
	if nodeVar == "" {
		apiErrorResponse(w, "error getting node", http.StatusBadRequest, nil)
		return
	}
	// Get node by identifier, scoped to this environment
	node, err := h.Nodes.GetByIdentifierEnv(nodeVar, env.ID)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	log.Debug().Msgf("Returned node %s", nodeVar)
	h.AuditLog.NodeAction(ctx[ctxUser], "viewed node "+nodeVar, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	// Project to the SPA-facing view that surfaces parsed-and-sanitized
	// enrichment fields (CPU cores, BIOS, hardware vendor/model) parsed from
	// the otherwise-hidden RawEnrollment blob. The enroll_secret inside that
	// blob is intentionally NOT in the projection — see pkg/types/node_view.go.
	view := types.ProjectNode(node)
	view.NodeKey = node.NodeKey
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, view)
}

// ActiveNodesHandler - GET Handler for active JSON nodes
// @Summary List active nodes
// @Description Returns active enrolled nodes for an environment.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} nodes.OsqueryNode
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/active [get]
func (h *HandlersApi) ActiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	// Get nodes — scoped to this environment (resolves audit finding U-DB-2)
	hours := h.Settings.InactiveHours(settings.NoEnvironmentID)
	nodeList, err := h.Nodes.GetByEnv(env.Name, nodes.ActiveNodes, hours)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodeList) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned active nodes")
	h.AuditLog.NodeAction(ctx[ctxUser], "viewed active nodes", strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeList)
}

// InactiveNodesHandler - GET Handler for inactive JSON nodes
// @Summary List inactive nodes
// @Description Returns inactive enrolled nodes for an environment.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} nodes.OsqueryNode
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/inactive [get]
func (h *HandlersApi) InactiveNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	// Get nodes — scoped to this environment (resolves audit finding U-DB-2)
	hours := h.Settings.InactiveHours(settings.NoEnvironmentID)
	nodeList, err := h.Nodes.GetByEnv(env.Name, nodes.InactiveNodes, hours)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodeList) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned inactive nodes")
	h.AuditLog.NodeAction(ctx[ctxUser], "viewed inactive nodes", strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeList)
}

// AllNodesHandler - GET Handler for all JSON nodes
// @Summary List all nodes
// @Description Returns all enrolled nodes for an environment.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} nodes.OsqueryNode
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/all [get]
func (h *HandlersApi) AllNodesHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get nodes — scoped to this environment (resolves audit finding U-DB-2)
	nodeList, err := h.Nodes.GetByEnv(env.Name, nodes.AllNodes, 0)
	if err != nil {
		apiErrorResponse(w, "error getting nodes", http.StatusInternalServerError, err)
		return
	}
	if len(nodeList) == 0 {
		apiErrorResponse(w, "no nodes", http.StatusNotFound, nil)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned all nodes")
	h.AuditLog.NodeAction(ctx[ctxUser], "viewed all nodes", strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, nodeList)
}

// DeleteNodeHandler - POST Handler to delete single node
// @Summary Delete node
// @Description Deletes a node from an environment.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.ApiNodeGenericRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/delete [post]
func (h *HandlersApi) DeleteNodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	var n types.ApiNodeGenericRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	if _, err := h.Nodes.GetByUUIDEnv(n.UUID, env.ID); err != nil {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if err := h.Nodes.ArchiveDeleteByUUID(n.UUID); err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	log.Debug().Msgf("Deleted node %s", n.UUID)
	h.AuditLog.NodeAction(ctx[ctxUser], "deleted node "+n.UUID, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "node deleted"})
}

// TagNodeHandler - POST Handler to tag a node
// @Summary Tag node
// @Description Adds or updates a tag on a node.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.ApiNodeTagRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/tag [post]
func (h *HandlersApi) TagNodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
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
	var t types.ApiNodeTagRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	if t.UUID == "" || t.Tag == "" {
		apiErrorResponse(w, "uuid and tag are required", http.StatusBadRequest, nil)
		return
	}
	// Get node by UUID
	n, err := h.Nodes.GetByUUIDEnv(t.UUID, env.ID)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	if err := h.Tags.TagNode(t.Tag, n, ctx[ctxUser], false, t.Type, t.Custom); err != nil {
		apiErrorResponse(w, "error tagging node", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Tagged node %s with %s", n.UUID, t.Tag)
	h.AuditLog.NodeAction(ctx[ctxUser], "tagged node "+n.UUID+" with "+t.Tag, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "node tagged"})
}

// LookupNodeHandler - POST Handler to lookup a node by identifier
// @Summary Lookup node
// @Description Looks up a node by UUID, hostname, or local name.
// @Tags nodes
// @Accept json
// @Produce json
// @Param request body types.ApiLookupRequest true "Request body"
// @Success 200 {object} nodes.OsqueryNode
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/lookup [post]
func (h *HandlersApi) LookupNodeHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var l types.ApiLookupRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	if l.Identifier == "" {
		apiErrorResponse(w, "error with identifier", http.StatusBadRequest, nil)
		return
	}
	n, err := h.Nodes.GetByIdentifier(l.Identifier)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		}
		return
	}
	log.Debug().Msgf("Looked up node %s", l.Identifier)
	h.AuditLog.NodeAction(ctx[ctxUser], "looked up node "+l.Identifier, strings.Split(r.RemoteAddr, ":")[0], n.ID)
	// Serialize and serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, n)
}

// NodesPagedHandler returns paginated, sorted, searchable nodes for an env.
// This is the canonical endpoint consumed by the React admin SPA.
//
// Query params:
//
//	status:    "all" | "active" | "inactive" (default "all")
//	q:         free-text search (case-insensitive partial match on uuid,
//	           hostname, localname, ip, username, osquery_user, platform, version)
//	sort:      one of nodes.SortableColumns keys (default "lastseen")
//	dir:       "asc" | "desc" (default "desc" for lastseen, "asc" otherwise)
//	page:      1-indexed page number (default 1)
//	page_size: 1..500 (default 50)
//
// @Summary List paginated nodes
// @Description Returns paginated, filtered, and sorted nodes for an environment.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param page query int false "Page number"
// @Param page_size query int false "Page size"
// @Param q query string false "Search query"
// @Param status query string false "Node status filter"
// @Param platform query string false "Platform filter"
// @Param sort query string false "Sort field"
// @Param order query string false "Sort order"
// @Success 200 {object} types.NodesPagedResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env} [get]
func (h *HandlersApi) NodesPagedHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// env from URL path
	envVar := r.PathValue("env")
	env, err := h.Envs.Get(envVar)
	if err != nil {
		// try by name for callers that pass an env name (legacy compat)
		envByName, err2 := h.Envs.GetByName(envVar)
		if err2 != nil {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		env = envByName
	}

	// auth context — user
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	// params
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = "all"
	}
	switch status {
	case "all", "active", "inactive":
	default:
		apiErrorResponse(w, "invalid status (all|active|inactive)", http.StatusBadRequest, nil)
		return
	}
	search := q.Get("q")
	dirParam := strings.ToLower(q.Get("dir"))
	sortCol := q.Get("sort")
	var desc bool
	switch dirParam {
	case "asc":
		desc = false
	case "desc":
		desc = true
	default:
		// No explicit direction: default to desc for time-based columns,
		// asc for everything else. Matches OpenAPI default of "desc" for
		// the most common SPA sort (lastseen).
		switch sortCol {
		case "", "lastseen", "firstseen":
			desc = true
		default:
			desc = false
		}
	}
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	// Platform bucket filter — empty string disables. Validated inside
	// applyPlatformBucket: unknown buckets become no-ops. We do still allow
	// the explicit value "other" so the SPA can offer an "Other" chip for
	// platforms that don't fit linux/darwin/windows.
	platformBucket := strings.ToLower(strings.TrimSpace(q.Get("platform")))
	switch platformBucket {
	case "", "linux", "darwin", "windows", "other":
		// allowed
	default:
		apiErrorResponse(w, "invalid platform (linux|darwin|windows|other)", http.StatusBadRequest, nil)
		return
	}

	hours := h.Settings.InactiveHours(settings.NoEnvironmentID)
	pageData, err := h.Nodes.GetByEnvPaged(env.Name, status, hours, search, page, pageSize, sortCol, desc, platformBucket)
	if err != nil {
		apiErrorResponse(w, "failed to query nodes", http.StatusInternalServerError, err)
		return
	}

	// Normalize page/pageSize back so the client sees what was actually applied.
	if pageSize <= 0 {
		pageSize = 50
	} else if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}
	totalPages := int((pageData.TotalItems + int64(pageSize) - 1) / int64(pageSize))
	if totalPages == 0 {
		totalPages = 1
	}

	log.Debug().Msgf("Returned paged nodes for env %s page %d", env.Name, page)
	h.AuditLog.NodeAction(ctx[ctxUser], "viewed paged nodes", strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.NodesPagedResponse{
		// ProjectNodes adds the parsed `system_info` enrichment block per row.
		// The enroll_secret inside RawEnrollment is intentionally excluded.
		Items:      types.ProjectNodes(pageData.Items),
		Page:       page,
		PageSize:   pageSize,
		TotalItems: pageData.TotalItems,
		TotalPages: totalPages,
	})
}
