package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// savedQueryView projects a storage row into the SPA-canonical envelope.
// Timestamps stay as time.Time so JSON-encoded output is RFC3339 — matches
// the OpenAPI date-time format and the SPA's formatRelative ISO parser.
func savedQueryView(s queries.SavedQuery) types.SavedQueryView {
	return types.SavedQueryView{
		ID:            s.ID,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
		Name:          s.Name,
		Creator:       s.Creator,
		Query:         s.Query,
		EnvironmentID: s.EnvironmentID,
		ExtraData:     s.ExtraData,
	}
}

// SavedQueriesListHandler - GET /api/v1/saved-queries/{env}
//
// Paginated, sorted, searchable list of saved queries for an environment.
// Query params: page, page_size, q (free-text), sort (column key), dir (asc|desc).
// @Summary List saved queries
// @Description Returns paginated saved queries for an environment.
// @Tags saved-queries
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param page query int false "Page number"
// @Param page_size query int false "Page size"
// @Param q query string false "Search query"
// @Success 200 {object} types.SavedQueriesPagedResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/saved-queries/{env} [get]
func (h *HandlersApi) SavedQueriesListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}
	search := q.Get("q")
	sortCol := q.Get("sort")
	desc := strings.ToLower(q.Get("dir")) != "asc"

	result, err := h.Queries.GetSavedByEnvPaged(env.ID, search, page, pageSize, sortCol, desc)
	if err != nil {
		apiErrorResponse(w, "error getting saved queries", http.StatusInternalServerError, err)
		return
	}
	items := make([]types.SavedQueryView, 0, len(result.Items))
	for _, s := range result.Items {
		items = append(items, savedQueryView(s))
	}
	var totalPages int
	if result.TotalItems > 0 {
		totalPages = int((result.TotalItems + int64(pageSize) - 1) / int64(pageSize))
	}
	resp := types.SavedQueriesPagedResponse{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		TotalItems: result.TotalItems,
		TotalPages: totalPages,
	}
	log.Debug().Msgf("Returned %d saved queries (page %d of %d)", len(items), page, totalPages)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// SavedQueryCreateHandler - POST /api/v1/saved-queries/{env}
//
// Body: { "name": string, "query": string }. Returns 201 with the created view,
// 409 if a saved query with that name already exists in the environment.
// @Summary Create saved query
// @Description Creates a saved query in an environment.
// @Tags saved-queries
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.SavedQueryCreateRequest true "Request body"
// @Success 200 {object} types.SavedQueryView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/saved-queries/{env} [post]
func (h *HandlersApi) SavedQueryCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	var body types.SavedQueryCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Query = strings.TrimSpace(body.Query)
	if body.Name == "" {
		apiErrorResponse(w, "name can not be empty", http.StatusBadRequest, nil)
		return
	}
	if body.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusBadRequest, nil)
		return
	}
	// The DB unique index on (name, environment_id) is the authoritative
	// gate (see pkg/queries.SavedQuery + ErrSavedQueryExists). The
	// SavedExists probe stays as a fast-path so the typical "this name
	// is already taken" case returns 409 without hitting Create at all;
	// races where two POSTs slip past SavedExists are caught by the
	// duplicate-key error from CreateSaved.
	if h.Queries.SavedExists(body.Name, env.ID) {
		apiErrorResponse(w, "saved query with that name already exists", http.StatusConflict, nil)
		return
	}

	creator := ctx[ctxUser]
	if err := h.Queries.CreateSaved(body.Name, body.Query, creator, env.ID); err != nil {
		if errors.Is(err, queries.ErrSavedQueryExists) {
			apiErrorResponse(w, "saved query with that name already exists", http.StatusConflict, err)
			return
		}
		apiErrorResponse(w, "error creating saved query", http.StatusInternalServerError, err)
		return
	}
	saved, err := h.Queries.GetSavedByEnv(body.Name, env.ID)
	if err != nil {
		apiErrorResponse(w, "error fetching newly created saved query", http.StatusInternalServerError, err)
		return
	}

	h.AuditLog.SavedQueryAction(creator, "create "+body.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Created saved query %s in env %s", body.Name, env.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, savedQueryView(saved))
}

// SavedQueryUpdateHandler - PATCH /api/v1/saved-queries/{env}/{name}
//
// Body: { "query": string }. Updates the SQL body only; the original creator
// is preserved. Returns the updated view.
// @Summary Update saved query
// @Description Updates a saved query in an environment.
// @Tags saved-queries
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param name path string true "Saved query name"
// @Param request body types.SavedQueryUpdateRequest true "Request body"
// @Success 200 {object} types.SavedQueryView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/saved-queries/{env}/{name} [patch]
func (h *HandlersApi) SavedQueryUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	name := r.PathValue("name")
	if envVar == "" || name == "" {
		apiErrorResponse(w, "missing env or name", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	var body types.SavedQueryUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	body.Query = strings.TrimSpace(body.Query)
	if body.Query == "" {
		apiErrorResponse(w, "query can not be empty", http.StatusBadRequest, nil)
		return
	}

	if err := h.Queries.UpdateSaved(name, body.Query, env.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "saved query not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error updating saved query", http.StatusInternalServerError, err)
		return
	}
	saved, err := h.Queries.GetSavedByEnv(name, env.ID)
	if err != nil {
		apiErrorResponse(w, "error fetching updated saved query", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SavedQueryAction(ctx[ctxUser], "update "+name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Updated saved query %s in env %s", name, env.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, savedQueryView(saved))
}

// SavedQueryDeleteHandler - DELETE /api/v1/saved-queries/{env}/{name}
// @Summary Delete saved query
// @Description Deletes a saved query in an environment.
// @Tags saved-queries
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param name path string true "Saved query name"
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
// @Router /api/v1/saved-queries/{env}/{name} [delete]
func (h *HandlersApi) SavedQueryDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	name := r.PathValue("name")
	if envVar == "" || name == "" {
		apiErrorResponse(w, "missing env or name", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	if err := h.Queries.DeleteSavedByEnv(name, env.ID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "saved query not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error deleting saved query", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SavedQueryAction(ctx[ctxUser], "delete "+name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Deleted saved query %s in env %s", name, env.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: fmt.Sprintf("saved query %s deleted", name)})
}
