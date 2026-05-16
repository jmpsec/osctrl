package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// EnvironmentCreateHandler - POST /api/v1/environments
//
// Body: { name, hostname, type? }. Generates a UUID, defaults config /
// schedule / packs / decorators / ATC to "{}", and persists the env.
// Returns 201 with the created TLSEnvironment. Super-admin only.
func (h *HandlersApi) EnvironmentCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.EnvCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	// Names are persisted lowercase so `Dev` and `dev` collide on the
	// uniqueIndex and so name-based lookups across the codebase don't
	// need to special-case casing. Filter validation runs against the
	// canonical form.
	body.Name = strings.ToLower(strings.TrimSpace(body.Name))
	body.Hostname = strings.TrimSpace(body.Hostname)
	if !environments.VerifyEnvFilters(body.Name, body.Icon, body.Type, body.Hostname) {
		apiErrorResponse(w, "invalid name, hostname, type, or icon", http.StatusBadRequest, nil)
		return
	}
	if h.Envs.Exists(body.Name) {
		apiErrorResponse(w, "environment with that name already exists", http.StatusConflict, nil)
		return
	}
	env := h.Envs.Empty(body.Name, body.Hostname)
	if body.Type != "" {
		env.Type = body.Type
	}
	if body.Icon != "" {
		env.Icon = body.Icon
	}
	env.Configuration = h.Envs.GenEmptyConfiguration(true)
	flags, err := h.Envs.GenerateFlags(env, "", "", h.OsqueryValues)
	if err != nil {
		apiErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
		return
	}
	env.Flags = flags
	if err := h.Envs.Create(&env); err != nil {
		// Race fallback: the Exists() check above is best-effort; if a
		// concurrent request inserted the same name between that check
		// and this Create, the uniqueIndex on tls_environments.name
		// raises gorm.ErrDuplicatedKey. Return 409 instead of 500 so
		// the SPA can distinguish the collision from a real DB error.
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			apiErrorResponse(w, "environment with that name already exists", http.StatusConflict, err)
			return
		}
		apiErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
		return
	}
	// Grant the creating user full access to the new environment so it shows up
	// in their env list immediately (matches the legacy admin behaviour).
	access := h.Users.GenEnvUserAccess([]string{env.UUID}, true, true, true, true)
	perms := h.Users.GenPermissions(ctx[ctxUser], h.ServiceName, access)
	if err := h.Users.CreatePermissions(perms); err != nil {
		log.Err(err).Msgf("env %s created but failed to grant creator permissions", env.Name)
	}
	// Auto-tag the environment for tag-based targeting.
	if !h.Tags.ExistsByEnv(env.Name, env.ID) {
		if err := h.Tags.NewTag(
			env.Name,
			"Tag for environment "+env.Name,
			"",
			env.Icon,
			ctx[ctxUser],
			env.ID,
			false,
			tags.TagTypeEnv,
			"",
		); err != nil {
			log.Err(err).Msgf("env %s created but failed to create env tag", env.Name)
		}
	}
	h.AuditLog.EnvAction(ctx[ctxUser], "create env "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Created environment %s (uuid=%s)", env.Name, env.UUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, env)
}

// EnvironmentUpdateHandler - PATCH /api/v1/environments/{env}
//
// Updates name / hostname / type / icon / debug_http / accept_enrolls.
// Other env fields go through the per-section endpoints. Super-admin only.
func (h *HandlersApi) EnvironmentUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	var body types.EnvUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	// Validate every supplied field with the same character-class
	// filters the create path uses. Without this gate a super-admin
	// (or a compromised super-admin session via a future CSRF gap)
	// can PATCH the env name to anything — including shell
	// metacharacters and newlines that downstream interpolators
	// (genPackageFilename → Content-Disposition, audit-log lines,
	// route paths) would happily embed unescaped.
	//
	patch := map[string]interface{}{}
	if body.Name != nil {
		// Persist env names lowercased — see EnvironmentCreateHandler for
		// the reasoning. Filter validation runs against the canonical
		// form so the regex character-class still matches.
		n := strings.ToLower(strings.TrimSpace(*body.Name))
		if !environments.EnvNameFilter(n) {
			apiErrorResponse(w, "invalid environment name", http.StatusBadRequest, fmt.Errorf("rejected name %q", *body.Name))
			return
		}
		if n != env.Name {
			// Pre-flight: reject a rename that would collide with an
			// existing env (best-effort, common case). The uniqueIndex
			// on tls_environments.name is the actual source of truth and
			// catches the TOCTOU race below.
			if h.Envs.Exists(n) {
				apiErrorResponse(w, "environment already exists", http.StatusConflict, fmt.Errorf("environment %s already exists", n))
				return
			}
			patch["name"] = n
		}
	}
	if body.Hostname != nil {
		host := strings.TrimSpace(*body.Hostname)
		if !environments.HostnameFilter(host) {
			apiErrorResponse(w, "invalid hostname", http.StatusBadRequest, fmt.Errorf("rejected hostname %q", *body.Hostname))
			return
		}
		if host != env.Hostname {
			patch["hostname"] = host
		}
	}
	if body.Type != nil {
		t := strings.TrimSpace(*body.Type)
		if !environments.EnvTypeFilter(t) {
			apiErrorResponse(w, "invalid environment type", http.StatusBadRequest, fmt.Errorf("rejected type %q", *body.Type))
			return
		}
		patch["type"] = t
	}
	if body.Icon != nil {
		icon := strings.TrimSpace(*body.Icon)
		if !environments.IconFilter(icon) {
			apiErrorResponse(w, "invalid icon", http.StatusBadRequest, fmt.Errorf("rejected icon %q", *body.Icon))
			return
		}
		patch["icon"] = icon
	}
	if body.DebugHTTP != nil {
		patch["debug_http"] = *body.DebugHTTP
	}
	if body.AcceptEnrolls != nil {
		patch["accept_enrolls"] = *body.AcceptEnrolls
	}
	if len(patch) == 0 {
		// Idempotent no-op — return the current env.
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
		return
	}
	if err := h.Envs.DB.Model(&env).Updates(patch).Error; err != nil {
		// Race fallback for the rename path: a concurrent PATCH could
		// have inserted the same target name between our Exists() check
		// above and this UPDATE. uniqueIndex catches it; translate to
		// 409 so the SPA can distinguish the collision from a real DB
		// error.
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			apiErrorResponse(w, "environment already exists", http.StatusConflict, err)
			return
		}
		apiErrorResponse(w, "error updating environment", http.StatusInternalServerError, err)
		return
	}
	updated, _ := h.Envs.Get(envVar)
	h.AuditLog.EnvAction(ctx[ctxUser], "update env "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Updated environment %s", env.Name)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, updated)
}

// EnvironmentDeleteHandler - DELETE /api/v1/environments/{env}
//
// Removes the environment. Super-admin only. Returns 200 with a message.
func (h *HandlersApi) EnvironmentDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	if err := h.Envs.Delete(envVar); err != nil {
		apiErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], "delete env "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Deleted environment %s", env.Name)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: fmt.Sprintf("environment %s deleted", env.Name)})
}

// EnvironmentConfigHandler - GET /api/v1/environments/config/{env}
//
// Returns the env's JSON-shaped config sections (options/schedule/packs/
// decorators/atc/flags) so the SPA's Monaco editor can render each section.
func (h *HandlersApi) EnvironmentConfigHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	resp := types.EnvConfigResponse{
		Options:    env.Options,
		Schedule:   env.Schedule,
		Packs:      env.Packs,
		Decorators: env.Decorators,
		ATC:        env.ATC,
		Flags:      env.Flags,
	}
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// EnvironmentConfigPatchHandler - PATCH /api/v1/environments/config/{env}
//
// Body: optional options/schedule/packs/decorators/atc/flags string fields.
// Each non-nil field is validated as JSON before persisting; an invalid
// payload is rejected with 400 (no partial writes).
func (h *HandlersApi) EnvironmentConfigPatchHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.EnvConfigPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	// Validate every supplied section is parseable JSON, and canonicalize
	// each value (trim whitespace, "" → "{}") into `normalized` so the
	// persistence calls below share the same source of truth as the
	// validation. Without this, the validator accepts an empty string
	// (treating it as "{}") while the update calls below would still
	// write the original empty string to the DB — downstream parsers
	// (osquery config generation, admin JSON view) trip on the empty
	// string and behave inconsistently with the validated shape.
	sections := map[string]*string{
		"options":    body.Options,
		"schedule":   body.Schedule,
		"packs":      body.Packs,
		"decorators": body.Decorators,
		"atc":        body.ATC,
		"flags":      body.Flags,
	}
	normalized := map[string]string{}
	for name, val := range sections {
		if val == nil {
			continue
		}
		s := strings.TrimSpace(*val)
		if s == "" {
			s = "{}"
		}
		var probe interface{}
		if err := json.Unmarshal([]byte(s), &probe); err != nil {
			apiErrorResponse(w, fmt.Sprintf("section %q is not valid JSON: %s", name, err.Error()), http.StatusBadRequest, err)
			return
		}
		normalized[name] = s
	}
	if v, ok := normalized["options"]; ok {
		if err := h.Envs.UpdateOptions(envVar, v); err != nil {
			apiErrorResponse(w, "error updating options", http.StatusInternalServerError, err)
			return
		}
	}
	if v, ok := normalized["schedule"]; ok {
		if err := h.Envs.UpdateSchedule(envVar, v); err != nil {
			apiErrorResponse(w, "error updating schedule", http.StatusInternalServerError, err)
			return
		}
	}
	if v, ok := normalized["packs"]; ok {
		if err := h.Envs.UpdatePacks(envVar, v); err != nil {
			apiErrorResponse(w, "error updating packs", http.StatusInternalServerError, err)
			return
		}
	}
	if v, ok := normalized["decorators"]; ok {
		if err := h.Envs.UpdateDecorators(envVar, v); err != nil {
			apiErrorResponse(w, "error updating decorators", http.StatusInternalServerError, err)
			return
		}
	}
	if v, ok := normalized["atc"]; ok {
		if err := h.Envs.UpdateATC(envVar, v); err != nil {
			apiErrorResponse(w, "error updating atc", http.StatusInternalServerError, err)
			return
		}
	}
	if v, ok := normalized["flags"]; ok {
		if err := h.Envs.DB.Model(&env).Update("flags", v).Error; err != nil {
			apiErrorResponse(w, "error updating flags", http.StatusInternalServerError, err)
			return
		}
	}
	h.AuditLog.ConfAction(ctx[ctxUser], "config patch on env "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	updated, _ := h.Envs.Get(envVar)
	resp := types.EnvConfigResponse{
		Options:    updated.Options,
		Schedule:   updated.Schedule,
		Packs:      updated.Packs,
		Decorators: updated.Decorators,
		ATC:        updated.ATC,
		Flags:      updated.Flags,
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// EnvironmentIntervalsPatchHandler - PATCH /api/v1/environments/intervals/{env}
//
// Body: { config_interval?, log_interval?, query_interval? }. Updates the
// three node-pull intervals atomically. Unsupplied fields are kept.
func (h *HandlersApi) EnvironmentIntervalsPatchHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.EnvIntervalsPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	cfg := env.ConfigInterval
	lg := env.LogInterval
	qr := env.QueryInterval
	if body.ConfigInterval != nil {
		if *body.ConfigInterval < 1 {
			apiErrorResponse(w, "config_interval must be >= 1", http.StatusBadRequest, nil)
			return
		}
		cfg = *body.ConfigInterval
	}
	if body.LogInterval != nil {
		if *body.LogInterval < 1 {
			apiErrorResponse(w, "log_interval must be >= 1", http.StatusBadRequest, nil)
			return
		}
		lg = *body.LogInterval
	}
	if body.QueryInterval != nil {
		if *body.QueryInterval < 1 {
			apiErrorResponse(w, "query_interval must be >= 1", http.StatusBadRequest, nil)
			return
		}
		qr = *body.QueryInterval
	}
	if err := h.Envs.UpdateIntervals(env.Name, cfg, lg, qr); err != nil {
		apiErrorResponse(w, "error updating intervals", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.ConfAction(ctx[ctxUser],
		fmt.Sprintf("intervals patch on env %s: config=%d log=%d query=%d", env.Name, cfg, lg, qr),
		strings.Split(r.RemoteAddr, ":")[0], env.ID)
	updated, _ := h.Envs.Get(envVar)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, updated)
}

// EnvironmentExpirationPatchHandler - PATCH /api/v1/environments/expiration/{env}
//
// Convenience wrapper around the existing enrollment lifecycle actions
// (extend / expire / rotate / not-expire), accepting one of those actions
// via JSON body instead of as a path segment. Mirrors the legacy
// EnvEnrollActionsHandler semantics for both enroll and remove paths.
func (h *HandlersApi) EnvironmentExpirationPatchHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.EnvExpirationPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	switch body.Action {
	case "extend":
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending enrollment", http.StatusInternalServerError, err)
			return
		}
	case "expire":
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring enrollment", http.StatusInternalServerError, err)
			return
		}
	case "rotate":
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating enrollment", http.StatusInternalServerError, err)
			return
		}
	case "not-expire":
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no expiration", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "action must be one of: extend, expire, rotate, not-expire", http.StatusBadRequest, nil)
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], body.Action+" enrollment for env "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	updated, _ := h.Envs.Get(envVar)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, updated)
}

// Suppress unused-import warning if environments package isn't referenced
// elsewhere in this file (it is — used by EnvUpdateRequest typing). This
// stub is a no-op kept to keep the import obvious.
var _ = environments.EnrollShell
