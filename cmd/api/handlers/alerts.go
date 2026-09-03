package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// alerts.go — management API for the alerting subsystem: rules CRUD,
// channels CRUD, history read, channel type registry, and the apply
// (hot-reload) command. Mirrors the log-sinks handler surface.

const alertsCommandTTL = logSinksCommandTTL

// alertRuleDTO is the JSON shape returned to clients.
type alertRuleDTO struct {
	ID              uint   `json:"id"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
	Name            string `json:"name"`
	EnvironmentID   uint   `json:"environment_id"`
	Source          string `json:"source"`
	NodeUUID        string `json:"node_uuid"`
	MatchType       string `json:"match_type"`
	MatchField      string `json:"match_field"`
	MatchValue      string `json:"match_value"`
	StatusSeverity  string `json:"status_severity"`
	CooldownMinutes int    `json:"cooldown_minutes"`
	ChannelIDs      []uint `json:"channel_ids"`
	Enabled         bool   `json:"enabled"`
	Info            string `json:"info"`
}

func toAlertRuleDTO(r alerts.AlertRule) alertRuleDTO {
	ids, _ := alerts.DecodeChannelIDs(r.ChannelIDs)
	return alertRuleDTO{
		ID:              r.ID,
		CreatedAt:       r.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       r.UpdatedAt.Format(time.RFC3339),
		Name:            r.Name,
		EnvironmentID:   r.EnvironmentID,
		Source:          r.Source,
		NodeUUID:        r.NodeUUID,
		MatchType:       r.MatchType,
		MatchField:      r.MatchField,
		MatchValue:      r.MatchValue,
		StatusSeverity:  r.StatusSeverity,
		CooldownMinutes: r.CooldownMinutes,
		ChannelIDs:      ids,
		Enabled:         r.Enabled,
		Info:            r.Info,
	}
}

// alertChannelDTO is the JSON shape returned to clients. Config is a
// decoded object with secrets redacted unless reveal=1.
type alertChannelDTO struct {
	ID            uint            `json:"id"`
	CreatedAt     string          `json:"created_at"`
	UpdatedAt     string          `json:"updated_at"`
	Name          string          `json:"name"`
	EnvironmentID uint            `json:"environment_id"`
	Type          string          `json:"type"`
	Enabled       bool            `json:"enabled"`
	Config        json.RawMessage `json:"config"`
	Info          string          `json:"info"`
}

func toAlertChannelDTO(c alerts.AlertChannel, reveal bool) alertChannelDTO {
	cfg := c.Config
	if !reveal {
		cfg = alerts.RedactedChannelConfig(c.Type, c.Config)
	}
	return alertChannelDTO{
		ID:            c.ID,
		CreatedAt:     c.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     c.UpdatedAt.Format(time.RFC3339),
		Name:          c.Name,
		EnvironmentID: c.EnvironmentID,
		Type:          c.Type,
		Enabled:       c.Enabled,
		Config:        json.RawMessage(cfg),
		Info:          c.Info,
	}
}

func (h *HandlersApi) requireAlertsAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use alerts API by user %s", ctx[ctxUser]))
		return "", false
	}
	return ctx[ctxUser], true
}

func (h *HandlersApi) alertsMgr(w http.ResponseWriter) (*alerts.Manager, bool) {
	if h.Alerts == nil {
		apiErrorResponse(w, "alerts not enabled", http.StatusServiceUnavailable, nil)
		return nil, false
	}
	return h.Alerts, true
}

// ─────────────────────────────── rules ───────────────────────────────

// AlertRulesListHandler — GET /api/v1/alerts/rules?env={id}
//
// @Summary List alert rules
// @Description Returns alert rule rows, optionally filtered by environment.
// @Tags alerts
// @Produce json
// @Param env query int false "Environment ID; omit to list all"
// @Success 200 {array} alertRuleDTO
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/rules [get]
func (h *HandlersApi) AlertRulesListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	envID, err := parseEnvFilter(r)
	if err != nil {
		apiErrorResponse(w, "invalid env filter", http.StatusBadRequest, err)
		return
	}
	rows, err := mgr.ListRules(envID)
	if err != nil {
		apiErrorResponse(w, "error listing alert rules", http.StatusInternalServerError, err)
		return
	}
	out := make([]alertRuleDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAlertRuleDTO(row))
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// AlertRuleGetHandler — GET /api/v1/alerts/rules/{id}
//
// @Summary Get one alert rule
// @Description Returns a single alert rule by ID.
// @Tags alerts
// @Produce json
// @Param id path int true "Rule ID"
// @Success 200 {object} alertRuleDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/rules/{id} [get]
func (h *HandlersApi) AlertRuleGetHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid rule id", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.GetRule(id)
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAlertRuleDTO(row))
}

// AlertRulesCreateHandler — POST /api/v1/alerts/rules
//
// @Summary Create an alert rule
// @Description Creates a new alert rule for the given environment (or global when environment_id is 0).
// @Tags alerts
// @Accept json
// @Produce json
// @Param request body types.AlertRuleCreateRequest true "Request body"
// @Success 201 {object} alertRuleDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/rules [post]
func (h *HandlersApi) AlertRulesCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	var body types.AlertRuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.CreateRule(alerts.AlertRule{
		Name:            body.Name,
		EnvironmentID:   body.EnvironmentID,
		Source:          body.Source,
		NodeUUID:        strings.TrimSpace(body.NodeUUID),
		MatchType:       body.MatchType,
		MatchField:      body.MatchField,
		MatchValue:      body.MatchValue,
		StatusSeverity:  body.StatusSeverity,
		CooldownMinutes: body.CooldownMinutes,
		ChannelIDs:      alerts.EncodeChannelIDs(body.ChannelIDs),
		Enabled:         body.Enabled,
		Info:            body.Info,
	})
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("created alert rule %q (source %s, env %d)", row.Name, row.Source, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, toAlertRuleDTO(row))
}

// AlertRulesUpdateHandler — PUT /api/v1/alerts/rules/{id}
//
// @Summary Update an alert rule
// @Description Replaces an existing alert rule's mutable fields.
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Rule ID"
// @Param request body types.AlertRuleCreateRequest true "Request body"
// @Success 200 {object} alertRuleDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/rules/{id} [put]
func (h *HandlersApi) AlertRulesUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid rule id", http.StatusBadRequest, err)
		return
	}
	var body types.AlertRuleCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.UpdateRule(id, alerts.AlertRule{
		Name:            body.Name,
		EnvironmentID:   body.EnvironmentID,
		Source:          body.Source,
		NodeUUID:        strings.TrimSpace(body.NodeUUID),
		MatchType:       body.MatchType,
		MatchField:      body.MatchField,
		MatchValue:      body.MatchValue,
		StatusSeverity:  body.StatusSeverity,
		CooldownMinutes: body.CooldownMinutes,
		ChannelIDs:      alerts.EncodeChannelIDs(body.ChannelIDs),
		Enabled:         body.Enabled,
		Info:            body.Info,
	})
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("updated alert rule %q (env %d)", row.Name, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAlertRuleDTO(row))
}

// AlertRulesDeleteHandler — DELETE /api/v1/alerts/rules/{id}
//
// @Summary Delete an alert rule
// @Description Deletes an alert rule by ID. Deletion takes effect on the next alert reload.
// @Tags alerts
// @Produce json
// @Param id path int true "Rule ID"
// @Success 204 "No content"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/rules/{id} [delete]
func (h *HandlersApi) AlertRulesDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid rule id", http.StatusBadRequest, err)
		return
	}
	if err := mgr.DeleteRule(id); err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("deleted alert rule %d", id), strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────────── channels ───────────────────────────────

// AlertChannelsListHandler — GET /api/v1/alerts/channels?env={id}&reveal={0|1}
//
// @Summary List alert channels
// @Description Returns alert channel rows. Secrets are redacted unless reveal=1 is passed by an admin.
// @Tags alerts
// @Produce json
// @Param env query int false "Environment ID; omit to list all"
// @Param reveal query int false "Pass 1 to include secret fields (admin only)"
// @Success 200 {array} alertChannelDTO
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels [get]
func (h *HandlersApi) AlertChannelsListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	envID, err := parseEnvFilter(r)
	if err != nil {
		apiErrorResponse(w, "invalid env filter", http.StatusBadRequest, err)
		return
	}
	rows, err := mgr.ListChannels(envID)
	if err != nil {
		apiErrorResponse(w, "error listing alert channels", http.StatusInternalServerError, err)
		return
	}
	reveal := parseReveal(r)
	out := make([]alertChannelDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAlertChannelDTO(row, reveal))
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// AlertChannelsTypesHandler — GET /api/v1/alerts/channels/types
//
// @Summary List supported alert channel types
// @Description Returns the channel type registry: type, description, whether the config carries secrets, and which JSON keys hold them.
// @Tags alerts
// @Produce json
// @Success 200 {array} types.AlertChannelTypeSpec
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels/types [get]
func (h *HandlersApi) AlertChannelsTypesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if _, ok := h.requireAlertsAdmin(w, r); !ok {
		return
	}
	specs := make([]types.AlertChannelTypeSpec, 0, len(alerts.ChannelRegistry))
	for _, typ := range alerts.SupportedChannelTypes() {
		spec := alerts.ChannelRegistry[typ]
		fields := make([]types.AlertFieldSpec, 0, len(spec.Fields))
		for _, f := range spec.Fields {
			fields = append(fields, types.AlertFieldSpec{
				Name:        f.Name,
				Label:       f.Label,
				Type:        f.Type,
				Required:    f.Required,
				Placeholder: f.Placeholder,
				Help:        f.Help,
				Default:     f.Default,
			})
		}
		specs = append(specs, types.AlertChannelTypeSpec{
			Type:         spec.Type,
			Description:  spec.Description,
			HasSecret:    spec.HasSecret,
			SecretFields: spec.SecretFields,
			Fields:       fields,
		})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, specs)
}

// AlertChannelsGetHandler — GET /api/v1/alerts/channels/{id}?reveal={0|1}
//
// @Summary Get one alert channel
// @Description Returns a single alert channel by ID. Secrets are redacted unless reveal=1.
// @Tags alerts
// @Produce json
// @Param id path int true "Channel ID"
// @Param reveal query int false "Pass 1 to include secret fields (admin only)"
// @Success 200 {object} alertChannelDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels/{id} [get]
func (h *HandlersApi) AlertChannelsGetHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid channel id", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.GetChannel(id)
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAlertChannelDTO(row, parseReveal(r)))
}

// AlertChannelsCreateHandler — POST /api/v1/alerts/channels
//
// @Summary Create an alert channel
// @Description Creates a new notification channel. Config is validated against the channel type registry.
// @Tags alerts
// @Accept json
// @Produce json
// @Param request body types.AlertChannelCreateRequest true "Request body"
// @Success 201 {object} alertChannelDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels [post]
func (h *HandlersApi) AlertChannelsCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	var body types.AlertChannelCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.CreateChannel(alerts.AlertChannel{
		Name:          body.Name,
		EnvironmentID: body.EnvironmentID,
		Type:          body.Type,
		Enabled:       body.Enabled,
		Config:        string(body.Config),
		Info:          body.Info,
	})
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("created alert channel %q (type %s, env %d)", row.Name, row.Type, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, toAlertChannelDTO(row, true))
}

// AlertChannelsTestHandler — POST /api/v1/alerts/channels/test
//
// Sends one synthetic notification through the posted config without
// storing it, so a channel can be verified from the editor before it is
// saved. No new capability: an admin could already save a channel and
// wait for it to fire — this just closes the feedback loop.
//
// @Summary Test an alert channel
// @Description Delivers a test notification through the posted channel config. Secrets left as "***" are merged from the stored channel named by id.
// @Tags alerts
// @Accept json
// @Produce json
// @Param request body types.AlertChannelTestRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 502 {object} types.ApiErrorResponse "Delivery failed"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels/test [post]
func (h *HandlersApi) AlertChannelsTestHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	var body types.AlertChannelTestRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	cfg := string(body.Config)
	// Editing an existing channel reads its secrets back as "***", so a
	// test of an untouched secret has to merge the stored value or it
	// would send the placeholder and fail for the wrong reason.
	if body.ID != 0 {
		prev, err := mgr.GetChannel(body.ID)
		if err != nil {
			respondAlertsErr(w, err)
			return
		}
		if body.Type == "" {
			body.Type = prev.Type
		}
		merged, err := alerts.MergeChannelSecrets(prev.Type, prev.Config, cfg)
		if err != nil {
			apiErrorResponse(w, "error merging channel secrets", http.StatusBadRequest, err)
			return
		}
		cfg = merged
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("tested alert channel (type %s, id %d)", body.Type, body.ID), strings.Split(r.RemoteAddr, ":")[0])
	if err := alerts.TestSend(body.Type, cfg); err != nil {
		// A bad config is the operator's input; anything else is the
		// relay refusing us, which is not a 400 and not our 500.
		if errors.Is(err, alerts.ErrInvalidChannelType) || errors.Is(err, alerts.ErrInvalidChannelConfig) {
			respondAlertsErr(w, err)
			return
		}
		apiErrorResponse(w, err.Error(), http.StatusBadGateway, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{
		Message: fmt.Sprintf("Test notification sent through the %s channel", body.Type),
	})
}

// AlertChannelsUpdateHandler — PUT /api/v1/alerts/channels/{id}
//
// @Summary Update an alert channel
// @Description Replaces an existing channel's mutable fields. A secret field set to "***" is merged from the previously stored value.
// @Tags alerts
// @Accept json
// @Produce json
// @Param id path int true "Channel ID"
// @Param request body types.AlertChannelCreateRequest true "Request body"
// @Success 200 {object} alertChannelDTO
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels/{id} [put]
func (h *HandlersApi) AlertChannelsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid channel id", http.StatusBadRequest, err)
		return
	}
	var body types.AlertChannelCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	prev, err := mgr.GetChannel(id)
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	merged, err := alerts.MergeChannelSecrets(prev.Type, prev.Config, string(body.Config))
	if err != nil {
		apiErrorResponse(w, "error merging channel secrets", http.StatusBadRequest, err)
		return
	}
	row, err := mgr.UpdateChannel(id, alerts.AlertChannel{
		Name:          body.Name,
		EnvironmentID: body.EnvironmentID,
		Type:          body.Type,
		Enabled:       body.Enabled,
		Config:        merged,
		Info:          body.Info,
	})
	if err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("updated alert channel %q (type %s, env %d)", row.Name, row.Type, row.EnvironmentID), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAlertChannelDTO(row, true))
}

// AlertChannelsDeleteHandler — DELETE /api/v1/alerts/channels/{id}
//
// @Summary Delete an alert channel
// @Description Deletes an alert channel by ID. Rules referencing it keep the dangling ID and the dispatcher skips it; deletion takes effect on the next alert reload.
// @Tags alerts
// @Produce json
// @Param id path int true "Channel ID"
// @Success 204 "No content"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/channels/{id} [delete]
func (h *HandlersApi) AlertChannelsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid channel id", http.StatusBadRequest, err)
		return
	}
	if err := mgr.DeleteChannel(id); err != nil {
		respondAlertsErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("deleted alert channel %d", id), strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────────── history + apply ───────────────────────────────

// AlertHistoryHandler — GET /api/v1/alerts/history?limit={n}
//
// @Summary Recent alert history
// @Description Returns the most recent dispatched alerts, newest first, capped at 500.
// @Tags alerts
// @Produce json
// @Param limit query int false "Maximum rows (default 100, max 500)"
// @Success 200 {array} alerts.AlertHistory
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/history [get]
func (h *HandlersApi) AlertHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	mgr, ok := h.alertsMgr(w)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := mgr.RecentHistory(limit)
	if err != nil {
		apiErrorResponse(w, "error listing alert history", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rows)
}

// AlertsApplyHandler — POST /api/v1/alerts/apply
//
// @Summary Apply alert changes (hot reload)
// @Description Queues a reload-alerts service command for osctrl-tls. The TLS process reloads its alert rule snapshot and resets the channel sender cache without restarting. The snapshot swap is atomic; in-flight matches finish against the old ruleset.
// @Tags alerts
// @Produce json
// @Success 202 {object} types.ServiceConfigApplyResponse "Reload requested"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Alerts disabled or service commands unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/alerts/apply [post]
func (h *HandlersApi) AlertsApplyHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAlertsAdmin(w, r)
	if !ok {
		return
	}
	if h.Alerts == nil {
		apiErrorResponse(w, "alerts not enabled", http.StatusServiceUnavailable, nil)
		return
	}
	if h.ServiceCommands == nil {
		apiErrorResponse(w, "service commands not available", http.StatusServiceUnavailable, nil)
		return
	}
	cmd, err := h.ServiceCommands.Request(config.ServiceTLS, servicecommands.ActionReloadAlerts, user, strings.Split(r.RemoteAddr, ":")[0], alertsCommandTTL)
	if err != nil {
		apiErrorResponse(w, "error requesting tls alerts reload", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("apply alerts reload command %s", cmd.CommandID), strings.Split(r.RemoteAddr, ":")[0])
	log.Info().Str("command", cmd.CommandID).Msgf("TLS alerts reload requested by %s", user)
	resp := serviceCommandResponse(cmd)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ServiceConfigApplyResponse{
		Service: config.ServiceTLS,
		Message: "Reload requested. osctrl-tls will reload its alert rule snapshot and channel sender cache after consuming the service command.",
		Command: &resp,
	})
}

// ─────────────────────────────── helpers ───────────────────────────────

func parseAlertID(r *http.Request, name string) (uint, error) {
	v := r.PathValue(name)
	if v == "" {
		return 0, fmt.Errorf("missing %s", name)
	}
	n, err := strconv.ParseUint(v, 10, strconv.IntSize)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return uint(n), nil
}

func respondAlertsErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, alerts.ErrRuleNotFound), errors.Is(err, alerts.ErrChannelNotFound):
		apiErrorResponse(w, "not found", http.StatusNotFound, err)
	case errors.Is(err, alerts.ErrRuleExists), errors.Is(err, alerts.ErrChannelExists):
		apiErrorResponse(w, "already exists", http.StatusConflict, err)
	// Echo the reason: "invalid value" told the operator nothing about
	// which field the registry rejected, or why a channel test refused to
	// build. These endpoints are admin-only.
	case errors.Is(err, alerts.ErrInvalidSource), errors.Is(err, alerts.ErrInvalidChannelType), errors.Is(err, alerts.ErrInvalidChannelConfig):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
	// Rule validation failures are operator input, not server faults —
	// they used to fall through to the 500 below, which told the SPA
	// nothing and read as an outage.
	case errors.Is(err, alerts.ErrInvalidRule):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
	case errors.Is(err, alerts.ErrTooManyRules):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "not found", http.StatusNotFound, err)
	default:
		// apiErrorResponse only logs at debug level, so a genuine 500
		// here was invisible in a normally-configured deployment.
		log.Error().Err(err).Msg("alerts request failed")
		apiErrorResponse(w, "error", http.StatusInternalServerError, err)
	}
}
