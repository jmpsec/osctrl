package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// AllTagsHandler - GET Handler for all JSON tags
func (h *HandlersApi) AllTagsHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
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
	if h.Settings.DebugService(config.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned tags")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
}

// TagEnvHandler - GET Handler to return one tag for one environment as JSON
func (h *HandlersApi) TagEnvHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Extract tag name
	tagVar := r.PathValue("name")
	if tagVar == "" {
		apiErrorResponse(w, "error getting tag name", http.StatusBadRequest, nil)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get tag
	exist, tag := h.Tags.ExistsGet(tagVar, env.ID)
	if !exist {
		apiErrorResponse(w, "error getting tag", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(config.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned tag")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tag)
}

// TagsEnvHandler - GET Handler to return tags for one environment as JSON
func (h *HandlersApi) TagsEnvHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Get tags
	tags, err := h.Tags.GetByEnv(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting tags", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(config.ServiceAPI) {
		log.Debug().Msg("DebugService: Returned tags")
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, tags)
}

// TagsActionHandler - POST Handler to create, update or delete tags
func (h *HandlersApi) TagsActionHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var t types.ApiTagsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var returnData string
	switch actionVar {
	case tags.ActionAdd:
		if h.Tags.ExistsByEnv(t.Name, env.ID) {
			apiErrorResponse(w, "error adding tag", http.StatusInternalServerError, fmt.Errorf("tag %s already exists", t.Name))
			return
		}
		if err := h.Tags.NewTag(t.Name, t.Description, t.Color, t.Icon, ctx[ctxUser], env.ID, false, t.TagType); err != nil {
			apiErrorResponse(w, "error with new tag", http.StatusInternalServerError, err)
			return
		}
		returnData = "tag added successfully"
	case tags.ActionEdit:
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
		}
		returnData = "tag updated successfully"
	case tags.ActionRemove:
		if err := h.Tags.DeleteGet(t.Name, env.ID); err != nil {
			apiErrorResponse(w, "error removing tag", http.StatusInternalServerError, err)
			return
		}
		returnData = "tag removed successfully"
	}
	// Serialize and serve JSON
	if h.Settings.DebugService(config.ServiceAPI) {
		log.Debug().Msgf("DebugService: Returned %s", returnData)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}
