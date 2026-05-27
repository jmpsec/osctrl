package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// SettingPatchHandler — PATCH /api/v1/settings/{service}/{name}
//
// Body shape (one of String, Boolean, Integer):
//
//	{ "string": "value" }
//	{ "boolean": true }
//	{ "integer": 42 }
//
// The handler reads the existing setting first to determine its type, then
// applies the matching typed setter. Mismatched payloads return 400. The
// setting must already exist (creation is the legacy admin's job); a missing
// setting → 404. Audit-log on success only.
// @Summary Update setting
// @Description Updates a mutable setting value.
// @Tags settings
// @Accept json
// @Produce json
// @Param service path string true "Service name"
// @Param name path string true "Setting name"
// @Param request body types.SettingPatchRequest true "Request body"
// @Success 200 {object} settings.SettingValue
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/settings/{service}/{name} [patch]
func (h *HandlersApi) SettingPatchHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "missing service", http.StatusBadRequest, nil)
		return
	}
	if !h.Settings.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusBadRequest, nil)
		return
	}
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "missing name", http.StatusBadRequest, nil)
		return
	}

	existing, err := h.Settings.RetrieveValue(service, name, settings.NoEnvironmentID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "setting not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error reading setting", http.StatusInternalServerError, err)
		return
	}

	var body types.SettingPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}

	switch existing.Type {
	case settings.TypeBoolean:
		if body.Boolean == nil {
			apiErrorResponse(w, "setting is boolean — provide `boolean` in body", http.StatusBadRequest, nil)
			return
		}
		if err := h.Settings.SetBoolean(*body.Boolean, service, name, settings.NoEnvironmentID); err != nil {
			apiErrorResponse(w, "error updating setting", http.StatusInternalServerError, err)
			return
		}
	case settings.TypeInteger:
		if body.Integer == nil {
			apiErrorResponse(w, "setting is integer — provide `integer` in body", http.StatusBadRequest, nil)
			return
		}
		if err := h.Settings.SetInteger(*body.Integer, service, name, settings.NoEnvironmentID); err != nil {
			apiErrorResponse(w, "error updating setting", http.StatusInternalServerError, err)
			return
		}
	case settings.TypeString:
		if body.String == nil {
			apiErrorResponse(w, "setting is string — provide `string` in body", http.StatusBadRequest, nil)
			return
		}
		if err := h.Settings.SetString(*body.String, service, name, existing.JSON, settings.NoEnvironmentID); err != nil {
			apiErrorResponse(w, "error updating setting", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "unsupported setting type", http.StatusInternalServerError, nil)
		return
	}

	updated, err := h.Settings.RetrieveValue(service, name, settings.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error reading updated setting", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(ctx[ctxUser], fmt.Sprintf("patch %s/%s", service, name), strings.Split(r.RemoteAddr, ":")[0])
	log.Debug().Msgf("Patched setting %s/%s", service, name)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, updated)
}
