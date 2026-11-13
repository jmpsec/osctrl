package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

const (
	santaMaxBody       = 64 << 10
	santaImportMaxBody = 4 << 20
)

// SantaConfigResponse is the environment config plus whether a token exists.
type SantaConfigResponse struct {
	santa.EnvConfig
	TokenSet bool `json:"token_set"`
}

// SantaConfigRequest is the settable part of the config.
type SantaConfigRequest struct {
	ClientMode            string `json:"client_mode"`
	BatchSize             uint32 `json:"batch_size"`
	EnableTransitiveRules bool   `json:"enable_transitive_rules"`
	// Deprecated: use removable_media; only read when it is empty (true means BLOCK).
	BlockUSBMount bool `json:"block_usb_mount"`
	// ALLOW | BLOCK | REMOUNT; empty means ALLOW
	RemovableMedia string `json:"removable_media"`
	// Required with REMOUNT: rdonly, noexec, nosuid, nobrowse, noowners, nodev, async, -j
	RemovableMediaFlags []string `json:"removable_media_flags"`
	// Override for encrypted volumes: ALLOW | BLOCK | REMOUNT; empty uses removable_media
	EncryptedRemovableMedia string `json:"encrypted_removable_media"`
	// Required with encrypted REMOUNT; same values as removable_media_flags
	EncryptedRemovableMediaFlags []string `json:"encrypted_removable_media_flags"`
}

// SantaTokenResponse carries the plaintext token, shown only once.
type SantaTokenResponse struct {
	Token string `json:"token"`
}

// SantaRuleRequest holds the user-settable rule fields.
type SantaRuleRequest struct {
	Identifier string `json:"identifier"`
	RuleType   string `json:"rule_type"`
	Policy     string `json:"policy"`
	CELExpr    string `json:"cel_expr"`
	CustomMsg  string `json:"custom_msg"`
	CustomURL  string `json:"custom_url"`
	Scope      string `json:"scope"`
	ScopeValue string `json:"scope_value"`
}

// SantaModeOverrideRequest sets the client mode for a tag or a node.
type SantaModeOverrideRequest struct {
	// tag | node
	Scope string `json:"scope"`
	// Tag name or node UUID
	ScopeValue string `json:"scope_value"`
	// MONITOR | LOCKDOWN
	ClientMode string `json:"client_mode"`
}

// SantaEventsResponse is one page of events.
type SantaEventsResponse struct {
	Events []santa.Event `json:"events"`
	Total  int64         `json:"total"`
	Page   int           `json:"page"`
}

// santaEnvironment resolves {env}, requires environment admin and returns the
// caller. It writes the error response itself.
func (h *HandlersApi) santaEnvironment(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, string, bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return environments.TLSEnvironment{}, "", false
	}
	if h.Santa == nil {
		apiErrorResponse(w, "santa not enabled", http.StatusServiceUnavailable, nil)
		return environments.TLSEnvironment{}, "", false
	}
	user := ctxVal.(ContextValue)[ctxUser]
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "env required", http.StatusBadRequest, nil)
		return environments.TLSEnvironment{}, "", false
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return environments.TLSEnvironment{}, "", false
	}
	if !h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return environments.TLSEnvironment{}, "", false
	}
	return env, user, true
}

func (h *HandlersApi) santaAudit(user, action string, r *http.Request, env environments.TLSEnvironment) {
	h.AuditLog.EnvAction(user, "santa: "+action, utils.GetIP(r), env.ID)
}

func scopeValueSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " scope_value=" + v
}

// SantaConfigGetHandler — GET /api/v1/santa/{env}/config
// @Summary Get the Santa sync configuration
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} SantaConfigResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/config [get]
func (h *HandlersApi) SantaConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	h.writeSantaConfig(w, env)
}

func (h *HandlersApi) writeSantaConfig(w http.ResponseWriter, env environments.TLSEnvironment) {
	cfg, err := h.Santa.Config(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting config", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK,
		SantaConfigResponse{EnvConfig: cfg, TokenSet: cfg.TokenHash != ""})
}

// SantaConfigPutHandler — PUT /api/v1/santa/{env}/config
// @Summary Update the Santa sync configuration
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaConfigRequest true "Config"
// @Success 200 {object} SantaConfigResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/config [put]
func (h *HandlersApi) SantaConfigPutHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var req SantaConfigRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	media := req.RemovableMedia
	if media == "" && req.BlockUSBMount {
		media = santa.MediaBlock
	}
	cfg := santa.EnvConfig{
		EnvironmentID: env.ID, ClientMode: req.ClientMode, BatchSize: req.BatchSize,
		EnableTransitiveRules: req.EnableTransitiveRules,
		RemovableMedia:        media, RemovableMediaFlags: req.RemovableMediaFlags,
		EncryptedRemovableMedia: req.EncryptedRemovableMedia, EncryptedRemovableMediaFlags: req.EncryptedRemovableMediaFlags,
	}
	if err := santa.ValidateConfig(&cfg); err != nil {
		apiErrorResponse(w, "invalid config: "+err.Error(), http.StatusBadRequest, nil)
		return
	}
	if err := h.Santa.SaveConfig(cfg); err != nil {
		apiErrorResponse(w, "error saving config", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "update config", r, env)
	h.writeSantaConfig(w, env)
}

// SantaTokenHandler — POST /api/v1/santa/{env}/token
// @Summary Rotate the Santa sync token
// @Description The plaintext token is returned once; the previous token stops working immediately.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} SantaTokenResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/token [post]
func (h *HandlersApi) SantaTokenHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	token, err := h.Santa.RotateToken(env.ID)
	if err != nil {
		apiErrorResponse(w, "error rotating token", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "rotate token", r, env)
	w.Header().Set("Cache-Control", "no-store")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, SantaTokenResponse{Token: token})
}

// SantaRulesHandler — GET /api/v1/santa/{env}/rules
// @Summary List Santa rules
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} santa.Rule
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/rules [get]
func (h *HandlersApi) SantaRulesHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	rules, err := h.Santa.Rules(env.ID)
	if err != nil {
		apiErrorResponse(w, "error listing rules", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rules)
}

// SantaRuleCreateHandler — POST /api/v1/santa/{env}/rules
// @Summary Create a Santa rule
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaRuleRequest true "Rule"
// @Success 201 {object} santa.Rule
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/rules [post]
func (h *HandlersApi) SantaRuleCreateHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var req SantaRuleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	rule := santa.Rule{
		EnvironmentID: env.ID, CreatedBy: user,
		Identifier: req.Identifier, RuleType: req.RuleType, Policy: req.Policy, CELExpr: req.CELExpr,
		CustomMsg: req.CustomMsg, CustomURL: req.CustomURL, Scope: req.Scope, ScopeValue: req.ScopeValue,
	}
	err := h.Santa.CreateRule(&rule)
	switch {
	case errors.Is(err, santa.ErrInvalidRule):
		apiErrorResponse(w, "invalid rule: "+err.Error(), http.StatusBadRequest, err)
		return
	case errors.Is(err, santa.ErrRuleExists):
		apiErrorResponse(w, "rule already exists", http.StatusConflict, err)
		return
	case err != nil:
		apiErrorResponse(w, "error creating rule", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, fmt.Sprintf("create rule %d %s", rule.ID, ruleAuditString(rule)), r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, rule)
}

func ruleAuditString(r santa.Rule) string {
	return fmt.Sprintf("%s %s %s scope=%s", r.RuleType, r.Identifier, r.Policy, r.Scope) + scopeValueSuffix(r.ScopeValue)
}

// SantaRuleUpdateHandler — PUT /api/v1/santa/{env}/rules/{id}
// @Summary Update a Santa rule
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Rule id"
// @Param body body SantaRuleRequest true "Rule"
// @Success 200 {object} santa.Rule
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/rules/{id} [put]
func (h *HandlersApi) SantaRuleUpdateHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "invalid rule id", http.StatusBadRequest, err)
		return
	}
	var req SantaRuleRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	before, err := h.Santa.Rule(env.ID, uint(id))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "rule not found", http.StatusNotFound, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error getting rule", http.StatusInternalServerError, err)
		return
	}
	rule := before
	rule.Identifier, rule.RuleType, rule.Policy, rule.CELExpr = req.Identifier, req.RuleType, req.Policy, req.CELExpr
	rule.CustomMsg, rule.CustomURL, rule.Scope, rule.ScopeValue = req.CustomMsg, req.CustomURL, req.Scope, req.ScopeValue
	err = h.Santa.UpdateRule(&rule)
	switch {
	case errors.Is(err, santa.ErrInvalidRule):
		apiErrorResponse(w, "invalid rule: "+err.Error(), http.StatusBadRequest, err)
		return
	case errors.Is(err, santa.ErrRuleExists):
		apiErrorResponse(w, "rule already exists", http.StatusConflict, err)
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "rule not found", http.StatusNotFound, err)
		return
	case err != nil:
		apiErrorResponse(w, "error updating rule", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, fmt.Sprintf("update rule %d %s -> %s", id, ruleAuditString(before), ruleAuditString(rule)), r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rule)
}

// SantaRuleDeleteHandler — DELETE /api/v1/santa/{env}/rules/{id}
// @Summary Delete a Santa rule
// @Tags santa
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Rule id"
// @Success 204
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/rules/{id} [delete]
func (h *HandlersApi) SantaRuleDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "invalid rule id", http.StatusBadRequest, err)
		return
	}
	rule, err := h.Santa.Rule(env.ID, uint(id))
	if err == nil {
		err = h.Santa.DeleteRule(env.ID, uint(id))
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "rule not found", http.StatusNotFound, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error deleting rule", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, fmt.Sprintf("delete rule %d %s", id, ruleAuditString(rule)), r, env)
	w.WriteHeader(http.StatusNoContent)
}

// SantaRulesImportHandler — POST /api/v1/santa/{env}/rules/import
// @Summary Import Santa rules in bulk
// @Description Classifies each rule as new, duplicate, conflicting or invalid. New rules are stored in one transaction, and only when no rule is conflicting or invalid; existing rules are never changed. With dry_run=true nothing is stored. The body is limited to 4 MiB. The export format is the list of rules from GET rules; extra fields such as id are ignored.
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param dry_run query bool false "Report only, store nothing"
// @Param body body []santa.RuleSpec true "Rules"
// @Success 200 {object} santa.ImportResult
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/rules/import [post]
func (h *HandlersApi) SantaRulesImportHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var specs []santa.RuleSpec
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaImportMaxBody)).Decode(&specs); err != nil {
		apiErrorResponse(w, "invalid request: expected a JSON list of rules of at most 4 MiB", http.StatusBadRequest, err)
		return
	}
	dryRun, _ := strconv.ParseBool(r.URL.Query().Get("dry_run"))
	res, err := h.Santa.ImportRules(env.ID, user, specs, !dryRun)
	if err != nil {
		apiErrorResponse(w, "error importing rules", http.StatusInternalServerError, err)
		return
	}
	if res.Applied {
		h.santaAudit(user, fmt.Sprintf("import rules new=%d duplicate=%d", res.New, res.Duplicate), r, env)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, res)
}

// SantaModeOverridesHandler — GET /api/v1/santa/{env}/modes
// @Summary List Santa client mode overrides
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} santa.ModeOverride
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/modes [get]
func (h *HandlersApi) SantaModeOverridesHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	overrides, err := h.Santa.ModeOverrides(env.ID)
	if err != nil {
		apiErrorResponse(w, "error listing mode overrides", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, overrides)
}

// SantaModeOverrideSetHandler — PUT /api/v1/santa/{env}/modes
// @Summary Set the Santa client mode for a tag or a node
// @Description Creates the override, or replaces the mode of the existing one for the same tag or node.
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaModeOverrideRequest true "Override"
// @Success 200 {object} santa.ModeOverride
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/modes [put]
func (h *HandlersApi) SantaModeOverrideSetHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var req SantaModeOverrideRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	o := santa.ModeOverride{EnvironmentID: env.ID, CreatedBy: user, Scope: req.Scope, ScopeValue: req.ScopeValue, ClientMode: req.ClientMode}
	err := h.Santa.SetModeOverride(&o)
	if errors.Is(err, santa.ErrInvalidOverride) {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error saving mode override", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, fmt.Sprintf("set mode override %s scope=%s scope_value=%s", o.ClientMode, o.Scope, o.ScopeValue), r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, o)
}

// SantaModeOverrideDeleteHandler — DELETE /api/v1/santa/{env}/modes/{id}
// @Summary Delete a Santa client mode override
// @Tags santa
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Override id"
// @Success 204
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/modes/{id} [delete]
func (h *HandlersApi) SantaModeOverrideDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "invalid override id", http.StatusBadRequest, err)
		return
	}
	o, err := h.Santa.DeleteModeOverride(env.ID, uint(id))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "mode override not found", http.StatusNotFound, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error deleting mode override", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, fmt.Sprintf("delete mode override %s scope=%s scope_value=%s", o.ClientMode, o.Scope, o.ScopeValue), r, env)
	w.WriteHeader(http.StatusNoContent)
}

// SantaMachinesHandler — GET /api/v1/santa/{env}/machines
// @Summary List Santa machines
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} santa.Machine
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/machines [get]
func (h *HandlersApi) SantaMachinesHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	machines, err := h.Santa.Machines(env.ID)
	if err != nil {
		apiErrorResponse(w, "error listing machines", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, machines)
}

// SantaEventsHandler — GET /api/v1/santa/{env}/events
// @Summary List Santa execution events
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param page query int false "Page (1-based)"
// @Param page_size query int false "Page size"
// @Param machine_id query string false "Only events of this machine (node UUID)"
// @Param decision query string false "Decision name or prefix, for example BLOCK"
// @Param sha256 query string false "Only events of this file hash"
// @Success 200 {object} SantaEventsResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/events [get]
func (h *HandlersApi) SantaEventsHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	q := r.URL.Query()
	evs, total, err := h.Santa.Events(env.ID, page, size, santa.EventFilter{
		MachineID: q.Get("machine_id"), Decision: q.Get("decision"), SHA256: q.Get("sha256"),
	})
	if errors.Is(err, santa.ErrInvalidEventFilter) {
		apiErrorResponse(w, "invalid decision filter", http.StatusBadRequest, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error listing events", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, SantaEventsResponse{Events: evs, Total: total, Page: max(page, 1)})
}

// SantaEffectiveRulesResponse is what a machine gets at its next sync.
type SantaEffectiveRulesResponse struct {
	Rules      []santa.Rule `json:"rules"`
	ClientMode string       `json:"client_mode"`
	ModeSource string       `json:"mode_source"`
}

// SantaEffectiveRulesHandler — GET /api/v1/santa/{env}/machines/{machineid}/rules
// @Summary List the Santa rules and client mode that apply to one node
// @Description The rules a node receives after scope resolution (node over tag over environment), and its client mode. The node does not need to have synced yet.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param machineid path string true "Node UUID"
// @Success 200 {object} SantaEffectiveRulesResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/machines/{machineid}/rules [get]
func (h *HandlersApi) SantaEffectiveRulesHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(r.PathValue("machineid"), env.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		return
	}
	nodeTags, err := h.Tags.GetTagsByNodeIDs([]uint{node.ID})
	if err != nil {
		apiErrorResponse(w, "error getting node tags", http.StatusInternalServerError, err)
		return
	}
	var names []string
	for _, t := range nodeTags[node.ID] {
		names = append(names, t.Name)
	}
	rules, err := h.Santa.EffectiveRules(env.ID, node.UUID, names)
	if err != nil {
		apiErrorResponse(w, "error listing rules", http.StatusInternalServerError, err)
		return
	}
	mode, source, err := h.Santa.EffectiveMode(env.ID, node.UUID, names)
	if err != nil {
		apiErrorResponse(w, "error getting client mode", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK,
		SantaEffectiveRulesResponse{Rules: rules, ClientMode: mode, ModeSource: source})
}
