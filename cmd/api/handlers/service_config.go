package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/serviceconfig"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// ServiceConfigHandler - GET Handler for all service config sections
// @Summary List all service config sections
// @Description Returns all service configuration sections across all services.
// @Tags service-config
// @Produce json
// @Success 200 {array} serviceconfig.ServiceConfig
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/service-config [get]
func (h *HandlersApi) ServiceConfigHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	if h.ServiceConfig == nil {
		apiErrorResponse(w, "service config not initialized", http.StatusInternalServerError, nil)
		return
	}
	sections, err := h.ServiceConfig.GetAll(serviceconfig.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting service config", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msg("Returned all service config sections")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, sections)
}

// ServiceConfigServiceHandler - GET Handler for all sections of one service
// @Summary List service config sections for a service
// @Description Returns all configuration sections for the given service.
// @Tags service-config
// @Produce json
// @Param service path string true "Service name"
// @Success 200 {array} serviceconfig.ServiceConfig
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/service-config/{service} [get]
func (h *HandlersApi) ServiceConfigServiceHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	if h.ServiceConfig == nil {
		apiErrorResponse(w, "service config not initialized", http.StatusInternalServerError, nil)
		return
	}
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "missing service", http.StatusBadRequest, nil)
		return
	}
	if !h.ServiceConfig.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusBadRequest, nil)
		return
	}
	sections, err := h.ServiceConfig.GetAllByService(service, serviceconfig.NoEnvironmentID)
	if err != nil {
		apiErrorResponse(w, "error getting service config", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Returned service config for %s", service)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, sections)
}

// ServiceConfigSectionHandler - GET Handler for a single config section
// @Summary Get one service config section
// @Description Returns a single configuration section by service and section name.
// @Tags service-config
// @Produce json
// @Param service path string true "Service name"
// @Param section path string true "Section name"
// @Success 200 {object} serviceconfig.ServiceConfig
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/service-config/{service}/{section} [get]
func (h *HandlersApi) ServiceConfigSectionHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	if h.ServiceConfig == nil {
		apiErrorResponse(w, "service config not initialized", http.StatusInternalServerError, nil)
		return
	}
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "missing service", http.StatusBadRequest, nil)
		return
	}
	if !h.ServiceConfig.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusBadRequest, nil)
		return
	}
	section := r.PathValue("section")
	if section == "" {
		apiErrorResponse(w, "missing section", http.StatusBadRequest, nil)
		return
	}
	if !h.ServiceConfig.VerifySection(service, section) {
		apiErrorResponse(w, "invalid section", http.StatusBadRequest, nil)
		return
	}
	sc, err := h.ServiceConfig.GetSection(service, section, serviceconfig.NoEnvironmentID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "section not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting section", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Returned service config %s/%s", service, section)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, sc)
}

// ServiceConfigUpdateHandler — PUT /api/v1/service-config/{service}/{section}
//
// Replaces the JSON value of an editable service config section. Only
// sections marked Editable=true in the SectionRegistry can be updated.
// The source is flipped to "db" so subsequent boots won't clobber the
// change. The body must be a JSON object with a "value" field containing
// the new JSON-encoded section value.
//
// Body shape:
//
//	{ "value": {"enableHttp": true, "showBody": false} }
//
// @Summary Update service config section
// @Description Replaces an editable service config section's JSON value.
// @Tags service-config
// @Accept json
// @Produce json
// @Param service path string true "Service name"
// @Param section path string true "Section name"
// @Param request body types.ServiceConfigUpdateRequest true "Request body"
// @Success 200 {object} serviceconfig.ServiceConfig
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/service-config/{service}/{section} [put]
func (h *HandlersApi) ServiceConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	if h.ServiceConfig == nil {
		apiErrorResponse(w, "service config not initialized", http.StatusInternalServerError, nil)
		return
	}
	service := r.PathValue("service")
	if service == "" {
		apiErrorResponse(w, "missing service", http.StatusBadRequest, nil)
		return
	}
	if !h.ServiceConfig.VerifyService(service) {
		apiErrorResponse(w, "invalid service", http.StatusBadRequest, nil)
		return
	}
	section := r.PathValue("section")
	if section == "" {
		apiErrorResponse(w, "missing section", http.StatusBadRequest, nil)
		return
	}
	if !h.ServiceConfig.VerifySection(service, section) {
		apiErrorResponse(w, "invalid section", http.StatusBadRequest, nil)
		return
	}

	var body types.ServiceConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	if len(body.Value) == 0 {
		apiErrorResponse(w, "missing value in request body", http.StatusBadRequest, nil)
		return
	}

	updated, err := h.ServiceConfig.UpdateSection(service, section, string(body.Value), serviceconfig.NoEnvironmentID)
	if err != nil {
		switch {
		case errors.Is(err, serviceconfig.ErrSectionNotEditable):
			apiErrorResponse(w, "section is not editable", http.StatusConflict, err)
		case errors.Is(err, gorm.ErrRecordNotFound):
			apiErrorResponse(w, "section not found", http.StatusNotFound, err)
		default:
			apiErrorResponse(w, "error updating section", http.StatusInternalServerError, err)
		}
		return
	}
	h.AuditLog.SettingsAction(ctx[ctxUser], fmt.Sprintf("put service-config %s/%s", service, section), strings.Split(r.RemoteAddr, ":")[0])
	log.Debug().Msgf("Updated service config %s/%s", service, section)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, updated)
}
