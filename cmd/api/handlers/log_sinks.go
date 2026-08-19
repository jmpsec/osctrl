package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/logsinks"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const logSinksCommandTTL = 2 * time.Minute

// logSinkDTO is the JSON shape returned to the SPA. It mirrors
// logsinks.LogSink but exposes Config as a json.RawMessage so the
// client receives the decoded object (with secrets redacted unless
// reveal=1 was passed) rather than a stringified blob. This keeps the
// frontend form code trivial.
type logSinkDTO struct {
	ID            uint            `json:"id"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
	Name          string          `json:"name"`
	EnvironmentID uint            `json:"environment_id"`
	Type          string          `json:"type"`
	Enabled       bool            `json:"enabled"`
	Order         int             `json:"order"`
	Config        json.RawMessage `json:"config"`
	Source        string          `json:"source"`
	Info          string          `json:"info"`
	BytesSent     int64           `json:"bytes_sent"`
	ExportsCount  int64           `json:"exports_count"`
}

func toLogSinkDTO(s logsinks.LogSink, reveal bool) logSinkDTO {
	cfg := s.Config
	if !reveal {
		cfg = logsinks.RedactedConfig(s.Type, s.Config)
	}
	return logSinkDTO{
		ID:            s.ID,
		CreatedAt:     s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     s.UpdatedAt.Format(time.RFC3339),
		Name:          s.Name,
		EnvironmentID: s.EnvironmentID,
		Type:          s.Type,
		Enabled:       s.Enabled,
		Order:         s.Order,
		Config:        json.RawMessage(cfg),
		Source:        s.Source,
		Info:          s.Info,
		BytesSent:     s.BytesSent,
		ExportsCount:  s.ExportsCount,
	}
}

func (h *HandlersApi) requireLogSinksAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use log-sinks API by user %s", ctx[ctxUser]))
		return "", false
	}
	return ctx[ctxUser], true
}

func parseReveal(r *http.Request) bool {
	return r.URL.Query().Get("reveal") == "1"
}

func parseEnvFilter(r *http.Request) (*uint, error) {
	v := r.URL.Query().Get("env")
	if v == "" {
		return nil, nil
	}
	n, err := strconv.ParseUint(v, 10, strconv.IntSize)
	if err != nil {
		return nil, fmt.Errorf("invalid env id: %w", err)
	}
	e := uint(n)
	return &e, nil
}

// LogSinksListHandler — GET /api/v1/log-sinks?env={id}&reveal={0|1}
//
// @Summary List log sinks
// @Description Returns log sink rows, optionally filtered by environment. Secrets are redacted unless reveal=1 is passed by an admin.
// @Tags log-sinks
// @Produce json
// @Param env query int false "Environment ID; omit to list all environments"
// @Param reveal query int false "Pass 1 to include secret fields in the config (admin only)"
// @Success 200 {array} logSinkDTO
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks [get]
func (h *HandlersApi) LogSinksListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	envID, err := parseEnvFilter(r)
	if err != nil {
		apiErrorResponse(w, "invalid env filter", http.StatusBadRequest, err)
		return
	}
	rows, err := h.LogSinks.List(envID)
	if err != nil {
		apiErrorResponse(w, "error listing log sinks", http.StatusInternalServerError, err)
		return
	}
	reveal := parseReveal(r)
	out := make([]logSinkDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, toLogSinkDTO(row, reveal))
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// LogSinksTypesHandler — GET /api/v1/log-sinks/types
//
// @Summary List supported log sink types
// @Description Returns the sink type registry: type, description, whether the config carries secrets, and which JSON keys hold them.
// @Tags log-sinks
// @Produce json
// @Success 200 {array} types.LogSinkTypeSpec
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/types [get]
func (h *HandlersApi) LogSinksTypesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if _, ok := h.requireLogSinksAdmin(w, r); !ok {
		return
	}
	specs := make([]types.LogSinkTypeSpec, 0, len(logsinks.Registry))
	for _, typ := range logsinks.SupportedTypes() {
		spec := logsinks.Registry[typ]
		fields := make([]types.LogSinkFieldSpec, 0, len(spec.Fields))
		for _, f := range spec.Fields {
			fields = append(fields, types.LogSinkFieldSpec{
				Name:        f.Name,
				Label:       f.Label,
				Type:        string(f.Type),
				Required:    f.Required,
				Secret:      f.Secret,
				Placeholder: f.Placeholder,
				Help:        f.Help,
				Options:     f.Options,
				Default:     f.Default,
			})
		}
		specs = append(specs, types.LogSinkTypeSpec{
			Type:         spec.Type,
			Description:  spec.Description,
			HasSecret:    spec.HasSecret,
			SecretFields: spec.SecretFields,
			Fields:       fields,
		})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, specs)
}

// LogSinksGetHandler — GET /api/v1/log-sinks/{id}?reveal={0|1}
//
// @Summary Get one log sink
// @Description Returns a single log sink by ID. Secrets are redacted unless reveal=1 is passed by an admin.
// @Tags log-sinks
// @Produce json
// @Param id path int true "Sink ID"
// @Param reveal query int false "Pass 1 to include secret fields (admin only)"
// @Success 200 {object} logSinkDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/{id} [get]
func (h *HandlersApi) LogSinksGetHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseLogSinkID(r)
	if err != nil {
		apiErrorResponse(w, "invalid sink id", http.StatusBadRequest, err)
		return
	}
	row, err := h.LogSinks.Get(id)
	if err != nil {
		if errors.Is(err, logsinks.ErrSinkNotFound) {
			apiErrorResponse(w, "log sink not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting log sink", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toLogSinkDTO(row, parseReveal(r)))
}

// LogSinksCreateHandler — POST /api/v1/log-sinks
//
// @Summary Create a log sink
// @Description Creates a new log sink instance for the given environment (or global when environment_id is 0).
// @Tags log-sinks
// @Accept json
// @Produce json
// @Param request body types.LogSinkCreateRequest true "Request body"
// @Success 201 {object} logSinkDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks [post]
func (h *HandlersApi) LogSinksCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	var body types.LogSinkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	row, err := h.LogSinks.Create(body.Name, body.Type, body.Enabled, body.Order, string(body.Config), body.EnvironmentID, body.Info)
	if err != nil {
		respondLogSinksErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("created log sink %q (type %s, env %d)", row.Name, row.Type, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, toLogSinkDTO(row, true))
}

// LogSinksUpdateHandler — PUT /api/v1/log-sinks/{id}
//
// @Summary Update a log sink
// @Description Replaces an existing log sink's mutable fields. A secret field set to "***" is merged from the previously stored value.
// @Tags log-sinks
// @Accept json
// @Produce json
// @Param id path int true "Sink ID"
// @Param request body types.LogSinkUpdateRequest true "Request body"
// @Success 200 {object} logSinkDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/{id} [put]
func (h *HandlersApi) LogSinksUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseLogSinkID(r)
	if err != nil {
		apiErrorResponse(w, "invalid sink id", http.StatusBadRequest, err)
		return
	}
	var body types.LogSinkUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	prev, err := h.LogSinks.Get(id)
	if err != nil {
		if errors.Is(err, logsinks.ErrSinkNotFound) {
			apiErrorResponse(w, "log sink not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting log sink", http.StatusInternalServerError, err)
		return
	}
	merged, err := logsinks.MergeSecrets(prev.Type, prev.Config, string(body.Config))
	if err != nil {
		apiErrorResponse(w, "error merging sink secrets", http.StatusBadRequest, err)
		return
	}
	row, err := h.LogSinks.Update(id, body.Name, body.Type, body.Enabled, body.Order, merged, body.Info)
	if err != nil {
		respondLogSinksErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("updated log sink %q (type %s, env %d)", row.Name, row.Type, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toLogSinkDTO(row, true))
}

// LogSinksDeleteHandler — DELETE /api/v1/log-sinks/{id}
//
// @Summary Delete a log sink
// @Description Deletes a log sink by ID. Deletion takes effect on the next apply/reload.
// @Tags log-sinks
// @Produce json
// @Param id path int true "Sink ID"
// @Success 204 "No content"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/{id} [delete]
func (h *HandlersApi) LogSinksDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseLogSinkID(r)
	if err != nil {
		apiErrorResponse(w, "invalid sink id", http.StatusBadRequest, err)
		return
	}
	if err := h.LogSinks.Delete(id); err != nil {
		if errors.Is(err, logsinks.ErrSinkNotFound) {
			apiErrorResponse(w, "log sink not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error deleting log sink", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("deleted log sink %d", id), strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusNoContent)
}

// LogSinksCloneHandler — POST /api/v1/log-sinks/clone
//
// @Summary Clone sinks from one environment to another
// @Description Copies all log sinks from a source environment (use 0 for global) to a target environment. With overwrite=false returns 409 if the target already has sinks.
// @Tags log-sinks
// @Accept json
// @Produce json
// @Param request body types.LogSinkCloneRequest true "Request body"
// @Success 200 {array} logSinkDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Target has sinks"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/clone [post]
func (h *HandlersApi) LogSinksCloneHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.LogSinks == nil {
		apiErrorResponse(w, "log sinks not initialized", http.StatusInternalServerError, nil)
		return
	}
	var body types.LogSinkCloneRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	cloned, err := h.LogSinks.CloneEnvironment(body.SourceEnvironmentID, body.TargetEnvironmentID, body.Overwrite)
	if err != nil {
		if errors.Is(err, logsinks.ErrTargetHasSinks) {
			apiErrorResponse(w, "target environment already has log sinks", http.StatusConflict, err)
			return
		}
		respondLogSinksErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("cloned log sinks env %d -> env %d (overwrite=%v)", body.SourceEnvironmentID, body.TargetEnvironmentID, body.Overwrite), strings.Split(r.RemoteAddr, ":")[0])
	out := make([]logSinkDTO, 0, len(cloned))
	for _, row := range cloned {
		out = append(out, toLogSinkDTO(row, true))
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// LogSinksApplyHandler — POST /api/v1/log-sinks/apply
//
// @Summary Apply log sink changes (hot reload)
// @Description Queues a reload-log-sinks service command for osctrl-tls. The TLS process rebuilds its per-environment exporter map from the log_sinks table and atomically swaps it in, closing the old sinks. In-flight logs to the old sinks may be dropped during the swap; no restart is required.
// @Tags log-sinks
// @Produce json
// @Success 202 {object} types.ServiceConfigApplyResponse "Reload requested"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Service commands unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/log-sinks/apply [post]
func (h *HandlersApi) LogSinksApplyHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireLogSinksAdmin(w, r)
	if !ok {
		return
	}
	if h.ServiceCommands == nil {
		apiErrorResponse(w, "service commands not available", http.StatusServiceUnavailable, nil)
		return
	}
	cmd, err := h.ServiceCommands.Request(config.ServiceTLS, servicecommands.ActionReloadLogSinks, user, strings.Split(r.RemoteAddr, ":")[0], logSinksCommandTTL)
	if err != nil {
		apiErrorResponse(w, "error requesting tls log sinks reload", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("apply log-sinks reload command %s", cmd.CommandID), strings.Split(r.RemoteAddr, ":")[0])
	log.Info().Str("command", cmd.CommandID).Msgf("TLS log sinks reload requested by %s", user)
	resp := serviceCommandResponse(cmd)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ServiceConfigApplyResponse{
		Service: config.ServiceTLS,
		Message: "Reload requested. osctrl-tls will rebuild its log sink exporters after consuming the service command. In-flight logs to the old sinks may be dropped during the swap.",
		Command: &resp,
	})
}

func parseLogSinkID(r *http.Request) (uint, error) {
	v := r.PathValue("id")
	if v == "" {
		return 0, fmt.Errorf("missing id")
	}
	n, err := strconv.ParseUint(v, 10, strconv.IntSize)
	if err != nil {
		return 0, fmt.Errorf("invalid id: %w", err)
	}
	return uint(n), nil
}

func respondLogSinksErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, logsinks.ErrInvalidSinkType):
		apiErrorResponse(w, "invalid log sink type", http.StatusBadRequest, err)
	case errors.Is(err, logsinks.ErrInvalidSinkConfig):
		apiErrorResponse(w, "invalid log sink configuration", http.StatusBadRequest, err)
	case errors.Is(err, logsinks.ErrSinkNotFound):
		apiErrorResponse(w, "log sink not found", http.StatusNotFound, err)
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "log sink not found", http.StatusNotFound, err)
	default:
		apiErrorResponse(w, "error", http.StatusInternalServerError, err)
	}
}
