package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// AllTagsHandler - GET Handler for all JSON tags
// @Summary List tags
// @Description Returns tags across environments.
// @Tags tags
// @Produce json
// @Success 200 {array} tags.AdminTag
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/tags [get]
func (h *HandlersApi) AllTagsHandler(w http.ResponseWriter, r *http.Request) {
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
	// Get tags
	tags, err := h.Tags.All()
	if err != nil {
		apiErrorResponse(w, "error getting tags", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msgf("Returned %d tags", len(tags))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
}

// TagEnvHandler - GET Handler to return one tag for one environment as JSON.
// Permission is scoped to env.UUID admin so non-super operators with admin
// rights on this specific environment can view its tags.
// @Summary Get environment tag
// @Description Returns one tag by name for an environment.
// @Tags tags
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param name path string true "Tag name"
// @Success 200 {object} tags.AdminTag
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/tags/{env}/{name} [get]
func (h *HandlersApi) TagEnvHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	tagVar := r.PathValue("name")
	if tagVar == "" {
		apiErrorResponse(w, "error getting tag name", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	exist, tag := h.Tags.ExistsGet(tagVar, env.ID)
	if !exist {
		apiErrorResponse(w, "tag not found", http.StatusNotFound, nil)
		return
	}
	log.Debug().Msg("Returned tag")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tag)
}

// TagsEnvHandler - GET Handler to return tags for one environment as JSON.
// Permission is scoped to env.UUID admin (see TagEnvHandler note).
// @Summary List environment tags
// @Description Returns tags for an environment.
// @Tags tags
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} tags.AdminTag
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/tags/{env} [get]
func (h *HandlersApi) TagsEnvHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	tagList, err := h.Tags.GetByEnv(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting tags", http.StatusInternalServerError, err)
		return
	}
	// Empty list is a valid state — never return 404 on listing.
	if tagList == nil {
		tagList = []tags.AdminTag{}
	}
	log.Debug().Msgf("Returned %d tags", len(tagList))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tagList)
}

// TagsActionHandler - POST Handler to create / update / delete tags. The
// action arrives as a URL path segment (legacy contract retained because
// Track 6 doesn't introduce new tag routes); body validation surfaces 400
// on parse error and 409 on duplicate-name conflicts.
// @Summary Execute tag action
// @Description Creates, updates, deletes, or applies tags in an environment.
// @Tags tags
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param action path string true "Tag action"
// @Param request body types.ApiTagsRequest true "Request body"
// @Success 200 {object} types.ApiDataResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/tags/{env}/{action} [post]
func (h *HandlersApi) TagsActionHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var t types.ApiTagsRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	if t.Name == "" {
		apiErrorResponse(w, "tag name can not be empty", http.StatusBadRequest, nil)
		return
	}
	var returnData string
	switch actionVar {
	case tags.ActionAdd:
		if h.Tags.ExistsByEnv(t.Name, env.ID) {
			apiErrorResponse(w, "tag with that name already exists in this environment", http.StatusConflict, nil)
			return
		}
		if err := h.Tags.NewTag(t.Name, t.Description, t.Color, t.Icon, ctx[ctxUser], env.ID, false, t.TagType, t.Custom); err != nil {
			apiErrorResponse(w, "error creating tag", http.StatusInternalServerError, err)
			return
		}
		returnData = "tag added successfully"
	case tags.ActionEdit:
		if !h.Tags.ExistsByEnv(t.Name, env.ID) {
			apiErrorResponse(w, "tag not found", http.StatusNotFound, nil)
			return
		}
		tag, err := h.Tags.Get(t.Name, env.ID)
		if err != nil {
			apiErrorResponse(w, "error getting tag", http.StatusInternalServerError, err)
			return
		}
		if t.Description != "" && t.Description != tag.Description {
			if err := h.Tags.ChangeDescription(&tag, t.Description); err != nil {
				apiErrorResponse(w, "error changing description", http.StatusInternalServerError, err)
				return
			}
		}
		if t.Color != "" && t.Color != tag.Color {
			if err := h.Tags.ChangeColor(&tag, t.Color); err != nil {
				apiErrorResponse(w, "error changing color", http.StatusInternalServerError, err)
				return
			}
		}
		if t.Icon != "" && t.Icon != tag.Icon {
			if err := h.Tags.ChangeIcon(&tag, t.Icon); err != nil {
				apiErrorResponse(w, "error changing icon", http.StatusInternalServerError, err)
				return
			}
		}
		if t.TagType != tag.TagType {
			if err := h.Tags.ChangeTagType(&tag, t.TagType); err != nil {
				apiErrorResponse(w, "error changing tag type", http.StatusInternalServerError, err)
				return
			}
			if err := h.Tags.ChangeCustom(&tag, tags.ValidateCustom(t.Custom)); err != nil {
				apiErrorResponse(w, "error changing custom", http.StatusInternalServerError, err)
				return
			}
		}
		if t.Custom != "" && t.Custom != tag.CustomTag {
			if err := h.Tags.ChangeCustom(&tag, t.Custom); err != nil {
				apiErrorResponse(w, "error changing custom", http.StatusInternalServerError, err)
				return
			}
		}
		returnData = "tag updated successfully"
	case tags.ActionRemove:
		if !h.Tags.ExistsByEnv(t.Name, env.ID) {
			apiErrorResponse(w, "tag not found", http.StatusNotFound, nil)
			return
		}
		if err := h.Tags.DeleteGet(t.Name, env.ID); err != nil {
			apiErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
			return
		}
		returnData = "tag removed successfully"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, nil)
		return
	}
	log.Debug().Msgf("Returned [%s]", returnData)
	h.AuditLog.TagAction(ctx[ctxUser], actionVar+" tag "+t.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}
