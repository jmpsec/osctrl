package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/serviceconfig"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const serviceCommandTTL = 2 * time.Minute

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

// ServiceConfigApplyHandler — POST /api/v1/service-config/apply
//
// Triggers a graceful shutdown of the API service so the process manager
// (systemd, docker, k8s) restarts it. On restart, Resolve applies all
// DB-edited config sections (source=db) over the YAML defaults, making the
// operator's changes live.
//
// The handler returns 202 immediately; the shutdown happens asynchronously
// after a short delay so the HTTP response completes. If RestartCh is nil
// (not wired), returns 503.
//
// @Summary Apply config changes and restart
// @Description Triggers a graceful service restart to apply DB-edited config changes.
// @Tags service-config
// @Produce json
// @Success 202 {object} types.ApiErrorResponse "Restart triggered"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/service-config/apply [post]
func (h *HandlersApi) ServiceConfigApplyHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.ServiceConfigApplyRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
			return
		}
	}
	service := body.Service
	if service == "" {
		service = config.ServiceAPI
	}
	switch service {
	case config.ServiceAPI:
		if h.RestartCh == nil {
			apiErrorResponse(w, "restart not available", http.StatusServiceUnavailable, nil)
			return
		}
		h.AuditLog.SettingsAction(ctx[ctxUser], "apply service-config api restart", strings.Split(r.RemoteAddr, ":")[0])
		log.Info().Msgf("Service config apply triggered by %s — initiating API restart", ctx[ctxUser])
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ServiceConfigApplyResponse{
			Service: config.ServiceAPI,
			Message: "Restart triggered. osctrl-api will restart shortly to apply config changes.",
		})
		h.RestartCh <- struct{}{}
	case config.ServiceTLS:
		if h.ServiceCommands == nil {
			apiErrorResponse(w, "service commands not available", http.StatusServiceUnavailable, nil)
			return
		}
		cmd, err := h.ServiceCommands.RequestRestart(config.ServiceTLS, ctx[ctxUser], strings.Split(r.RemoteAddr, ":")[0], serviceCommandTTL)
		if err != nil {
			apiErrorResponse(w, "error requesting tls restart", http.StatusInternalServerError, err)
			return
		}
		h.AuditLog.SettingsAction(ctx[ctxUser], fmt.Sprintf("apply service-config tls restart command %s", cmd.CommandID), strings.Split(r.RemoteAddr, ":")[0])
		log.Info().Str("command", cmd.CommandID).Msgf("TLS restart requested by %s", ctx[ctxUser])
		resp := serviceCommandResponse(cmd)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ServiceConfigApplyResponse{
			Service: config.ServiceTLS,
			Message: "Restart requested. osctrl-tls will restart after consuming the service command.",
			Command: &resp,
		})
	default:
		apiErrorResponse(w, "invalid service", http.StatusBadRequest, nil)
	}
}

// ServiceCommandHandler — GET /api/v1/service-config/commands/{command_id}
func (h *HandlersApi) ServiceCommandHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	if h.ServiceCommands == nil {
		apiErrorResponse(w, "service commands not available", http.StatusServiceUnavailable, nil)
		return
	}
	commandID := r.PathValue("command_id")
	if commandID == "" {
		apiErrorResponse(w, "missing command id", http.StatusBadRequest, nil)
		return
	}
	cmd, err := h.ServiceCommands.Get(commandID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "command not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting command", http.StatusInternalServerError, err)
		return
	}
	resp := serviceCommandResponse(cmd)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

func serviceCommandResponse(cmd servicecommands.ServiceCommand) types.ServiceCommandResponse {
	return types.ServiceCommandResponse{
		CommandID:     cmd.CommandID,
		TargetService: cmd.TargetService,
		Action:        cmd.Action,
		Status:        cmd.Status(time.Now()),
		RequestedBy:   cmd.RequestedBy,
		RequestedFrom: cmd.RequestedFrom,
		CreatedAt:     cmd.CreatedAt,
		ExpiresAt:     cmd.ExpiresAt,
		ConsumedAt:    cmd.ConsumedAt,
		ConsumedBy:    cmd.ConsumedBy,
		RecoveredAt:   cmd.RecoveredAt,
		RecoveredBy:   cmd.RecoveredBy,
	}
}
