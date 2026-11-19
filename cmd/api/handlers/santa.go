package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
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
	// Seconds between full syncs: 0 for the Santa default (600), otherwise 60 to 86400.
	FullSyncIntervalSeconds uint32 `json:"full_sync_interval_seconds"`
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
	// Base https URL of the osctrl UI; when set, the block dialog links to the approval request page. Empty turns requests off
	ApprovalURL string `json:"approval_url"`
	// Alert channel IDs told about each new approval request, at most 10. Needs approval_url. Changing it requires superuser
	NotifyChannels []uint `json:"notify_channels"`
	// Votes that allow a blocked file on each voter's machine; 0 is off. Needs approval_url
	VoteLocalThreshold uint32 `json:"vote_local_threshold"`
	// Votes that allow the file in the whole environment; 0 is off, and it cannot be below the local threshold. Needs approval_url
	VoteGlobalThreshold uint32 `json:"vote_global_threshold"`
	// Overrides the action of MDM-deployed file access rules: NONE | AUDIT_ONLY | DISABLE; empty leaves the clients unchanged
	OverrideFileAccessAction string `json:"override_file_access_action"`
	// Clients hash the bundle of a blocked binary and upload its other binaries when osctrl asks
	EnableBundles bool `json:"enable_bundles"`
	// Upload every execution decision, not only blocks and would-be blocks
	EnableAllEventUpload bool `json:"enable_all_event_upload"`
	// Skip uploading executions that LOCKDOWN would block
	DisableUnknownEventUpload bool `json:"disable_unknown_event_upload"`
	// Executions from matching paths are allowed when no rule matches; empty is off. At most 1024 characters
	AllowedPathRegex string `json:"allowed_path_regex"`
	// Executions from matching paths are blocked when no rule matches; checked before allowed_path_regex. Empty is off
	BlockedPathRegex string `json:"blocked_path_regex"`
	// https URL of the block dialog button, with Santa placeholders such as %file_sha%; overrides the approval request link
	EventDetailURL string `json:"event_detail_url"`
	// Label of the block dialog button, at most 32 characters
	EventDetailText string `json:"event_detail_text"`
	// IdP groups whose members' machines get a tag of the environment (at most 100), matched on Santa's primary user
	GroupTags []santa.GroupTag `json:"group_tags"`
	// How the primary user matches an osctrl user for group_tags: "" (exact username, any case), local_part (username before "@") or email (account email). Ambiguous matches get no tags
	GroupMatch string `json:"group_match"`
	// Hold changes that weaken enforcement until another environment admin approves them (see /api/v1/changes). Turning it off is one of them
	RequireSecondAdmin bool `json:"require_second_admin"`
	// osctrl users who decide approval requests without being environment admins, at most 100. Adding one counts as weakening enforcement
	ApproverUsers []string `json:"approver_users"`
	// IdP groups whose members (by the groups last stored from SSO or SCIM) decide approval requests, at most 100. Adding one counts as weakening enforcement
	ApproverGroups []string `json:"approver_groups"`
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
	// Temporary MONITOR mode for 1 to 24 hours, with scope node and MONITOR only; 0 is permanent
	Hours uint `json:"hours"`
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

// santaDecider is santaEnvironment for the approval queue: environment admins
// and the environment's approvers pass. admin tells them apart.
func (h *HandlersApi) santaDecider(w http.ResponseWriter, r *http.Request) (env environments.TLSEnvironment, user string, admin bool, ok bool) {
	env, user, admin, approver, ok := h.santaAccess(w, r)
	if ok && !admin && !approver {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return env, user, false, false
	}
	return env, user, admin, ok
}

// santaAccess resolves {env} and the caller's Santa roles without refusing
// either; it writes the error response itself when ok is false.
func (h *HandlersApi) santaAccess(w http.ResponseWriter, r *http.Request) (env environments.TLSEnvironment, user string, admin, approver, ok bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	if h.Santa == nil {
		apiErrorResponse(w, "santa not enabled", http.StatusServiceUnavailable, nil)
		return
	}
	user = ctxVal.(ContextValue)[ctxUser]
	env, err := h.Envs.Get(r.PathValue("env"))
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, env.UUID) {
		return env, user, true, false, true
	}
	cfg, err := h.Santa.Config(env.ID)
	if err == nil {
		approver, err = h.Santa.IsApprover(cfg, user)
	}
	if err != nil {
		apiErrorResponse(w, "error checking approvers", http.StatusInternalServerError, err)
		return env, user, false, false, false
	}
	return env, user, false, approver, true
}

// SantaAccessResponse is what the caller may do on the Santa page.
type SantaAccessResponse struct {
	// Environment admin: the whole Santa page
	Admin bool `json:"admin"`
	// Approver: the Requests tab only
	Approver bool `json:"approver"`
}

// SantaAccessHandler — GET /api/v1/santa/{env}/access
// @Summary What the caller may do on the Santa page
// @Description Any signed-in account. admin is environment admin; approver is a listed approver user or a member of an approver group (by the groups last stored from SSO or SCIM).
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} SantaAccessResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/access [get]
func (h *HandlersApi) SantaAccessHandler(w http.ResponseWriter, r *http.Request) {
	_, _, admin, approver, ok := h.santaAccess(w, r)
	if !ok {
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, SantaAccessResponse{Admin: admin, Approver: approver})
}

func (h *HandlersApi) santaAudit(user, action string, r *http.Request, env environments.TLSEnvironment) {
	h.AuditLog.EnvAction(user, "santa: "+action, utils.GetIP(r), env.ID)
}

// readJSONBody reads at most max bytes and decodes them into v. The raw bytes
// identify the request for change approval.
func readJSONBody(w http.ResponseWriter, r *http.Request, max int64, v any) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		return nil, err
	}
	return b, json.Unmarshal(b, v)
}

// santaHeld holds a Santa action that weakens enforcement for a second admin
// when the environment requires one. It returns true when the caller must stop:
// the response (202 or an error) is written.
func (h *HandlersApi) santaHeld(w http.ResponseWriter, r *http.Request, env environments.TLSEnvironment, user, action string, body []byte) bool {
	cfg, err := h.Santa.Config(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting config", http.StatusInternalServerError, err)
		return true
	}
	if !cfg.RequireSecondAdmin {
		return false
	}
	return !h.secondAdmin(w, r, env, user, "santa: "+action, body)
}

// santaConfigRisks lists what a config update weakens: switching the
// environment to MONITOR, a new allowed path regex, turning off the second
// admin requirement, or new approvers. Empty means nothing.
func santaConfigRisks(prev, next santa.EnvConfig) string {
	s := ""
	if next.ClientMode == "MONITOR" && prev.ClientMode != "MONITOR" {
		s += " client_mode=MONITOR"
	}
	if next.AllowedPathRegex != "" && next.AllowedPathRegex != prev.AllowedPathRegex {
		s += " allowed_path_regex=" + next.AllowedPathRegex
	}
	if prev.RequireSecondAdmin && !next.RequireSecondAdmin {
		s += " require_second_admin=false"
	}
	if added := addedNames(prev.ApproverUsers, next.ApproverUsers); added != "" {
		s += " approver_users+=" + added
	}
	if added := addedNames(prev.ApproverGroups, next.ApproverGroups); added != "" {
		s += " approver_groups+=" + added
	}
	return s
}

// addedNames lists the names in next that prev lacks, comma-separated.
func addedNames(prev, next []string) string {
	var added []string
	for _, n := range next {
		if !slices.Contains(prev, n) {
			added = append(added, n)
		}
	}
	return strings.Join(added, ",")
}

// santaEnvAllow reports whether a rule can allow executions environment-wide.
// CEL rules count: their expression may allow.
func santaEnvAllow(scope, policy string) bool {
	return scope == "env" && policy != "BLOCKLIST" && policy != "SILENT_BLOCKLIST"
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
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
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
	body, err := readJSONBody(w, r, santaMaxBody, &req)
	if err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	media := req.RemovableMedia
	if media == "" && req.BlockUSBMount {
		media = santa.MediaBlock
	}
	cfg := santa.EnvConfig{
		EnvironmentID: env.ID, ClientMode: req.ClientMode, BatchSize: req.BatchSize, FullSyncIntervalSeconds: req.FullSyncIntervalSeconds,
		EnableTransitiveRules: req.EnableTransitiveRules,
		RemovableMedia:        media, RemovableMediaFlags: req.RemovableMediaFlags,
		EncryptedRemovableMedia: req.EncryptedRemovableMedia, EncryptedRemovableMediaFlags: req.EncryptedRemovableMediaFlags,
		ApprovalURL: req.ApprovalURL, NotifyChannels: req.NotifyChannels,
		VoteLocalThreshold: req.VoteLocalThreshold, VoteGlobalThreshold: req.VoteGlobalThreshold,
		OverrideFileAccessAction: req.OverrideFileAccessAction,
		EnableBundles:            req.EnableBundles, EnableAllEventUpload: req.EnableAllEventUpload,
		DisableUnknownEventUpload: req.DisableUnknownEventUpload,
		AllowedPathRegex:          req.AllowedPathRegex, BlockedPathRegex: req.BlockedPathRegex,
		EventDetailURL: req.EventDetailURL, EventDetailText: req.EventDetailText,
		GroupTags: req.GroupTags, GroupMatch: req.GroupMatch, RequireSecondAdmin: req.RequireSecondAdmin,
		ApproverUsers: req.ApproverUsers, ApproverGroups: req.ApproverGroups,
	}
	if err := santa.ValidateConfig(&cfg); err != nil {
		apiErrorResponse(w, "invalid config: "+err.Error(), http.StatusBadRequest, nil)
		return
	}
	for _, gt := range cfg.GroupTags {
		if !h.Tags.ExistsByEnv(gt.Tag, env.ID) {
			apiErrorResponse(w, fmt.Sprintf("invalid config: tag %q does not exist in the environment", gt.Tag), http.StatusBadRequest, nil)
			return
		}
	}
	for _, u := range cfg.ApproverUsers {
		if !h.Users.Exists(u) {
			apiErrorResponse(w, fmt.Sprintf("invalid config: user %q does not exist", u), http.StatusBadRequest, nil)
			return
		}
	}
	if code, err := h.santaCheckNotifyChannels(r, env, user, cfg.NotifyChannels); err != nil {
		apiErrorResponse(w, err.Error(), code, fmt.Errorf("attempt by %s", user))
		return
	}
	prev, err := h.Santa.Config(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting config", http.StatusInternalServerError, err)
		return
	}
	if risky := santaConfigRisks(prev, cfg); risky != "" && h.santaHeld(w, r, env, user, "update config"+risky, body) {
		return
	}
	if err := h.Santa.SaveConfig(cfg); err != nil {
		apiErrorResponse(w, "error saving config", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "update config", r, env)
	h.writeSantaConfig(w, env)
}

// santaRecordGroups keeps the IdP groups of an SSO login for Santa group tags.
// nil groups mean the provider has no groups claim configured, so the stored
// groups are left as they are, and so are the groups of a user SCIM provisions.
// A failure is logged and never blocks the login.
func (h *HandlersApi) santaRecordGroups(username string, groups []string) {
	if h.Santa == nil || groups == nil {
		return
	}
	if h.SCIM != nil {
		if managed, err := h.SCIM.Managed(username); err != nil || managed {
			if err != nil {
				log.Err(err).Str("username", username).Msg("santa: error checking SCIM")
			}
			return
		}
	}
	if err := h.Santa.SetUserGroups(username, groups); err != nil {
		log.Err(err).Str("username", username).Msg("santa: error storing IdP groups")
	}
}

// santaCheckNotifyChannels guards a change of the notification channels.
// Notifications put requester- and client-written text into the channels, so
// like log-content alert rules the change needs superuser. Each channel must
// exist and be global or belong to the environment. ids is sorted and unique.
func (h *HandlersApi) santaCheckNotifyChannels(r *http.Request, env environments.TLSEnvironment, user string, ids []uint) (int, error) {
	prev, err := h.Santa.Config(env.ID)
	if err != nil {
		return http.StatusInternalServerError, errors.New("error getting config")
	}
	if slices.Equal(ids, prev.NotifyChannels) {
		return 0, nil
	}
	if !h.Users.HasRoleContext(r.Context(), user, users.RoleSuperuser) {
		return http.StatusForbidden, errors.New("changing the notification channels requires superuser")
	}
	if len(ids) > 0 && h.Alerts == nil {
		return http.StatusBadRequest, errors.New("alerts are not enabled")
	}
	for _, id := range ids {
		ch, err := h.Alerts.GetChannel(id)
		if err != nil || (ch.EnvironmentID != alerts.NoEnvironmentID && ch.EnvironmentID != env.ID) {
			return http.StatusBadRequest, fmt.Errorf("alert channel %d is not available to this environment", id)
		}
	}
	return 0, nil
}

// SantaTokenHandler — POST /api/v1/santa/{env}/token
// @Summary Rotate the Santa sync token
// @Description The plaintext token is returned once; the previous token stops working immediately.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} SantaTokenResponse
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
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
	if h.santaHeld(w, r, env, user, "rotate token", nil) {
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
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
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
	body, err := readJSONBody(w, r, santaMaxBody, &req)
	if err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	rule := santa.Rule{
		EnvironmentID: env.ID, CreatedBy: user,
		Identifier: req.Identifier, RuleType: req.RuleType, Policy: req.Policy, CELExpr: req.CELExpr,
		CustomMsg: req.CustomMsg, CustomURL: req.CustomURL, Scope: req.Scope, ScopeValue: req.ScopeValue,
	}
	// Validate first so an invalid rule is not held for approval.
	if err := santa.ValidateRule(&rule); err != nil {
		apiErrorResponse(w, "invalid rule: "+err.Error(), http.StatusBadRequest, err)
		return
	}
	if santaEnvAllow(rule.Scope, rule.Policy) && h.santaHeld(w, r, env, user, "create rule "+ruleAuditString(rule), body) {
		return
	}
	err = h.Santa.CreateRule(&rule)
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
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
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
	body, err := readJSONBody(w, r, santaMaxBody, &req)
	if err != nil {
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
	if err := santa.ValidateRule(&rule); err != nil {
		apiErrorResponse(w, "invalid rule: "+err.Error(), http.StatusBadRequest, err)
		return
	}
	// Editing the message of an existing environment-wide allow rule is not
	// held; making one, or changing what it allows, is.
	sameAllow := santaEnvAllow(before.Scope, before.Policy) && before.RuleType == rule.RuleType &&
		before.Identifier == rule.Identifier && before.Policy == rule.Policy && before.CELExpr == rule.CELExpr
	if santaEnvAllow(rule.Scope, rule.Policy) && !sameAllow &&
		h.santaHeld(w, r, env, user, fmt.Sprintf("update rule %d -> %s", id, ruleAuditString(rule)), body) {
		return
	}
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
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
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
	body, err := readJSONBody(w, r, santaImportMaxBody, &specs)
	if err != nil {
		apiErrorResponse(w, "invalid request: expected a JSON list of rules of at most 4 MiB", http.StatusBadRequest, err)
		return
	}
	dryRun, _ := strconv.ParseBool(r.URL.Query().Get("dry_run"))
	if !dryRun {
		allow := 0
		for _, s := range specs {
			if santaEnvAllow(s.Scope, s.Policy) {
				allow++
			}
		}
		if allow > 0 && h.santaHeld(w, r, env, user, fmt.Sprintf("import rules count=%d env_allow=%d", len(specs), allow), body) {
			return
		}
	}
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
// @Description Creates the override, or replaces the mode of the existing one for the same tag or node; the result is permanent. With hours (1 to 24), scope node and MONITOR, it is temporary instead: the machine must have synced, it cannot replace a permanent node override (409), and it stops applying when it expires, reverting at the machine's first sync after that.
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaModeOverrideRequest true "Override"
// @Success 200 {object} santa.ModeOverride
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/modes [put]
func (h *HandlersApi) SantaModeOverrideSetHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var req SantaModeOverrideRequest
	body, err := readJSONBody(w, r, santaMaxBody, &req)
	if err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	if req.ClientMode == "MONITOR" && h.santaHeld(w, r, env, user,
		fmt.Sprintf("set mode override MONITOR scope=%s scope_value=%s hours=%d", req.Scope, req.ScopeValue, req.Hours), body) {
		return
	}
	o := santa.ModeOverride{EnvironmentID: env.ID, CreatedBy: user, Scope: req.Scope, ScopeValue: req.ScopeValue, ClientMode: req.ClientMode}
	switch {
	case req.Hours == 0:
		err = h.Santa.SetModeOverride(&o)
	case req.Scope != "node" || req.ClientMode != "MONITOR":
		err = fmt.Errorf("%w: hours are only valid for MONITOR on a node", santa.ErrInvalidOverride)
	default:
		o, err = h.Santa.GrantMonitor(env.ID, req.ScopeValue, req.Hours, user)
	}
	switch {
	case errors.Is(err, santa.ErrInvalidOverride):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	case errors.Is(err, santa.ErrUnknownMachine):
		apiErrorResponse(w, "this machine has not synced with the environment", http.StatusNotFound, err)
		return
	case errors.Is(err, santa.ErrPermanentOverride):
		apiErrorResponse(w, err.Error(), http.StatusConflict, err)
		return
	case err != nil:
		apiErrorResponse(w, "error saving mode override", http.StatusInternalServerError, err)
		return
	}
	action := fmt.Sprintf("set mode override %s scope=%s scope_value=%s", o.ClientMode, o.Scope, o.ScopeValue)
	if o.ExpiresAt != nil {
		action = fmt.Sprintf("grant temporary MONITOR machine=%s hours=%d expires=%s", o.ScopeValue, req.Hours, o.ExpiresAt.UTC().Format(time.RFC3339))
	}
	h.santaAudit(user, action, r, env)
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

// SantaFileAccessEventsResponse is one page of file access events.
type SantaFileAccessEventsResponse struct {
	Events []santa.FileAccessEvent `json:"events"`
	Total  int64                   `json:"total"`
	Page   int                     `json:"page"`
}

// SantaFileAccessEventsHandler — GET /api/v1/santa/{env}/file-access-events
// @Summary List Santa file access events
// @Description Requires environment admin. Violations of file access rules deployed to the clients through MDM, newest first, kept 30 days. Every field but the IDs is written by Santa clients.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param page query int false "Page (1-based)"
// @Param page_size query int false "Page size"
// @Param machine_id query string false "Only events of this machine (node UUID)"
// @Success 200 {object} SantaFileAccessEventsResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/file-access-events [get]
func (h *HandlersApi) SantaFileAccessEventsHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	evs, total, err := h.Santa.FileAccessEvents(env.ID, page, size, q.Get("machine_id"))
	if err != nil {
		apiErrorResponse(w, "error listing file access events", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, SantaFileAccessEventsResponse{Events: evs, Total: total, Page: max(page, 1)})
}

// SantaBinaryHandler — GET /api/v1/santa/{env}/binaries/{sha256}
// @Summary Get what the stored events say about one binary
// @Description Requires environment admin. Identity fields (names, signing chain, bundle) come from the file's newest event and are written by Santa clients. First and last seen, the event counts and the machine count only cover the events osctrl still keeps (30 days). Rules lists every rule of the environment naming the file, its team ID, signing ID, CDHash or leaf certificate. 404 when the environment has no event for the hash.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param sha256 path string true "SHA-256 of the file"
// @Success 200 {object} santa.Binary
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/binaries/{sha256} [get]
func (h *HandlersApi) SantaBinaryHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	b, err := h.Santa.Binary(env.ID, r.PathValue("sha256"))
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "no events for this file", http.StatusNotFound, err)
		return
	case err != nil:
		apiErrorResponse(w, "error getting binary", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, b)
}

// SantaReportHandler — GET /api/v1/santa/{env}/reports
// @Summary Santa reports: ready for lockdown, top blocked, rule coverage gaps
// @Description Requires environment admin. Computed from the events osctrl received in the last days days. Ready for lockdown lists the machines assigned MONITOR at their last preflight with their ALLOW_UNKNOWN count (executions LOCKDOWN would have blocked); a machine is ready with none and a sync in the window. Top blocked ranks BLOCK_* events by binary and by team ID. Coverage gaps rank the binaries most executed with no rule deciding them (ALLOW_UNKNOWN or BLOCK_UNKNOWN). Each ranked list has at most 20 entries. Event fields are written by Santa clients.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param days query int false "Window in days, 1 to 30 (default 14)"
// @Success 200 {object} santa.Report
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/reports [get]
func (h *HandlersApi) SantaReportHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	days := santa.DefaultReportDays
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			apiErrorResponse(w, "days must be a number", http.StatusBadRequest, nil)
			return
		}
		days = n
	}
	rep, err := h.Santa.Report(env.ID, days)
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error computing report", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rep)
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
