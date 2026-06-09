package handlers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// Define targets to be used to retrieve an environment map
var (
	EnvMapTargets = map[string]bool{
		"id":   true,
		"uuid": true,
		"name": true,
	}
)

// denyEnv emits a 403 AND an audit-log entry pinned to the env handler's
// resource class. Used by the env-handler family for every deny branch
// so cross-tenant probes leave an SoC-alertable trail. The path comes
// from r.URL.Path; envID is 0 (NoEnvironment) when the deny happened
// before env resolution.
func (h *HandlersApi) denyEnv(w http.ResponseWriter, r *http.Request, ctx ContextValue, envID uint, reason string) {
	h.AuditLog.Denied(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], reason, auditlog.LogTypeEnvironment, envID)
	apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("denied: %s for user %s", reason, ctx[ctxUser]))
}

// projectEnvironmentView strips the env-secret-bearing fields from
// TLSEnvironment to produce the SPA-canonical low-privilege envelope.
// Callers MUST use this when serving env data to a non-admin (UserLevel /
// QueryLevel / CarveLevel) user.
func projectEnvironmentView(env environments.TLSEnvironment) types.TLSEnvironmentView {
	return types.TLSEnvironmentView{
		ID:             env.ID,
		CreatedAt:      env.CreatedAt,
		UpdatedAt:      env.UpdatedAt,
		UUID:           env.UUID,
		Name:           env.Name,
		Hostname:       env.Hostname,
		Type:           env.Type,
		Icon:           env.Icon,
		DebugHTTP:      env.DebugHTTP,
		ConfigTLS:      env.ConfigTLS,
		ConfigInterval: env.ConfigInterval,
		LoggingTLS:     env.LoggingTLS,
		LogInterval:    env.LogInterval,
		QueryTLS:       env.QueryTLS,
		QueryInterval:  env.QueryInterval,
		CarvesTLS:      env.CarvesTLS,
		AcceptEnrolls:  env.AcceptEnrolls,
		EnrollExpire:   env.EnrollExpire,
		RemoveExpire:   env.RemoveExpire,
	}
}

// EnvironmentHandler - GET Handler to return one environment by UUID as JSON
func (h *HandlersApi) EnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by UUID
	env, err := h.Envs.Get(envVar)
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.UserLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	// Decide projection by privilege level: admins on this env (or
	// super-admins) receive the full storage struct including secret /
	// certificate / flags. UserLevel operators receive the low-privilege
	// view that omits enroll credentials.
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	if h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		log.Debug().Msgf("Returned environment %s (admin view)", env.Name)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, env)
		return
	}
	log.Debug().Msgf("Returned environment %s (low-priv view)", env.Name)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, projectEnvironmentView(env))
}

// EnvironmentMapHandler - GET Handler to return one environment as JSON
func (h *HandlersApi) EnvironmentMapHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
		return
	}
	// Check if target is valid
	if !EnvMapTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		h.denyEnv(w, r, ctx, auditlog.NoEnvironment, "permission check failed")
		return
	}
	// Prepare map by target
	var envMap interface{}
	var err error
	switch targetVar {
	case "id":
		envMap, err = h.Envs.GetMapByID()
	case "uuid":
		envMap, err = h.Envs.GetMapByString()
	case "name":
		envMap, err = h.Envs.GetMapByString()
	}
	if err != nil {
		apiErrorResponse(w, "error getting environments map", http.StatusInternalServerError, err)
		return
	}
	// Serialize and serve JSON
	log.Debug().Msg("Returned environments map")
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, envMap)
}

// EnvironmentsHandler - GET Handler to return all environments as JSON.
//
// Super-admins see every env; non-super-admins get the subset where
// their EnvAccess.User OR EnvAccess.Admin is true (the read-surface
// gate elsewhere in the API). The previous super-admin-only gate
// meant a non-super-admin user with valid env permissions couldn't
// even populate the SPA's env switcher — their nav read "No
// environments configured" even though they had access to envs.
func (h *HandlersApi) EnvironmentsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	requester := ctx[ctxUser]
	envAll, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "error getting environments", http.StatusInternalServerError, err)
		return
	}
	var out []any
	if h.Users.IsAdmin(requester) {
		for _, e := range envAll {
			out = append(out, e)
		}
	} else {
		access, gerr := h.Users.GetAccess(requester)
		if gerr != nil {
			access = nil
		}
		for _, e := range envAll {
			ea := access[e.UUID]
			if ea.Admin {
				out = append(out, e)
			} else if ea.User {
				out = append(out, projectEnvironmentView(e))
			}
		}
	}
	if out == nil {
		out = []any{}
	}
	log.Debug().Msgf("Returned %d environment(s) to %s", len(out), requester)
	h.AuditLog.Visit(requester, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// EnvEnrollHandler - GET Handler to return node enrollment values (secret, certificate, one-liner) for an environment as JSON
func (h *HandlersApi) EnvEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Get context data and check access. The enroll endpoint exposes the
	// env's enroll secret (directly via target=secret, indirectly via the
	// one-liners that embed it in the URL, and via target=flags). That
	// secret is the only credential needed to enroll nodes via osctrl-tls,
	// so it must be gated to AdminLevel on the env, not UserLevel.
	//
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusBadRequest, nil)
		return
	}
	var returnData string
	switch targetVar {
	case settings.DownloadSecret:
		returnData = env.Secret
	case settings.DownloadCert:
		returnData = env.Certificate
	case settings.DownloadFlags:
		returnData = env.Flags
	case settings.DownloadFlagsLinux:
		returnData = substitutePlatformPaths(env.Flags, env.Name, "/etc/osquery", "/")
	case settings.DownloadFlagsMac:
		returnData = substitutePlatformPaths(env.Flags, env.Name, "/private/var/osquery", "/")
	case settings.DownloadFlagsWin:
		returnData = substitutePlatformPaths(env.Flags, env.Name, "C:\\Program Files\\osquery", "\\")
	case settings.DownloadFlagsFreeBSD:
		returnData = substitutePlatformPaths(env.Flags, env.Name, "/usr/local/etc", "/")
	case environments.EnrollShell:
		returnData, err = environments.QuickAddOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			return
		}
	case environments.EnrollPowershell:
		returnData, err = environments.QuickAddOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Serialize and serve JSON. Don't log the payload — it contains the
	// enroll secret.
	log.Debug().Msgf("Returned enroll data for environment %s target=%s", env.Name, targetVar)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvRemoveHandler - GET Handler to return node removal values for an environment as JSON
func (h *HandlersApi) EnvRemoveHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	// Get context data and check access. The remove one-liners embed the
	// remove-secret in the URL, so the endpoint must be AdminLevel-gated
	// just like the enroll variant.
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	// Extract target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error getting target", http.StatusInternalServerError, nil)
		return
	}
	var returnData string
	switch targetVar {
	case environments.RemoveShell:
		returnData, err = environments.QuickRemoveOneLinerShell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating sh one-liner", http.StatusInternalServerError, err)
			return
		}
	case environments.RemovePowershell:
		returnData, err = environments.QuickRemoveOneLinerPowershell((env.Certificate != ""), env)
		if err != nil {
			apiErrorResponse(w, "error generating ps1 one-liner", http.StatusInternalServerError, err)
			return
		}
	default:
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, fmt.Errorf("invalid target %s", targetVar))
		return
	}
	// Serialize and serve JSON. Don't log the payload — it embeds the
	// remove secret.
	log.Debug().Msgf("Returned remove data for environment %s target=%s", env.Name, targetVar)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: returnData})
}

// EnvEnrollActionsHandler - POST Handler to perform actions (extend, expire) in enroll values
func (h *HandlersApi) EnvEnrollActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error extending enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment expired successfully"
	case settings.ActionRotate:
		if err := h.Envs.RotateEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating enrollment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireEnroll(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no expiration", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "enrollment set to not expire"
	case settings.SetMacPackage:
		if err := h.Envs.UpdatePkgPackage(env.UUID, e.MacPkgURL); err != nil {
			apiErrorResponse(w, "error setting PKG", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "PKG updated successfully"
	case settings.SetMsiPackage:
		if err := h.Envs.UpdateMsiPackage(env.UUID, e.MsiPkgURL); err != nil {
			apiErrorResponse(w, "error setting MSI", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "MSI updated successfully"
	case settings.SetDebPackage:
		if err := h.Envs.UpdateDebPackage(env.UUID, e.DebPkgURL); err != nil {
			apiErrorResponse(w, "error setting DEB", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "DEB updated successfully"
	case settings.SetRpmPackage:
		if err := h.Envs.UpdateRpmPackage(env.UUID, e.RpmPkgURL); err != nil {
			apiErrorResponse(w, "error setting RPM", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "RPM updated successfully"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		return
	}
	// Return query name as serialized response
	log.Debug().Msgf("Returned data for environment %s : %s", env.Name, msgReturn)
	h.AuditLog.EnvAction(ctx[ctxUser], actionVar+" enrollment for environment "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvRemoveActionsHandler - POST Handler to perform actions (extend, expire) in remove values
func (h *HandlersApi) EnvRemoveActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error getting environment", http.StatusBadRequest, nil)
		return
	}
	// Get environment by name
	env, err := h.Envs.Get(envVar)
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	// Extract action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	var e types.ApiActionsRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch actionVar {
	case settings.ActionExtend:
		if err := h.Envs.ExtendRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error extending remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove extended successfully"
	case settings.ActionExpire:
		if err := h.Envs.ExpireRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error expiring remove", http.StatusInternalServerError, err)
			return
		}
	case settings.ActionRotate:
		if err := h.Envs.RotateRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error rotating remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove rotated successfully"
	case settings.ActionNotexpire:
		if err := h.Envs.NotExpireRemove(env.UUID); err != nil {
			apiErrorResponse(w, "error setting no remove", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "remove set to not expire"
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", actionVar))
		return
	}
	// Return query name as serialized response
	log.Debug().Msgf("Returned data for environment %s : %s", env.Name, msgReturn)
	h.AuditLog.EnvAction(ctx[ctxUser], actionVar+" removal for environment "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvActionsHandler - POST Handler to perform actions (create, delete, edit) on environments
func (h *HandlersApi) EnvActionsHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Get context data and check access
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		h.denyEnv(w, r, ctx, auditlog.NoEnvironment, "permission check failed")
		return
	}
	var e types.ApiEnvRequest
	// Parse request JSON body
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusInternalServerError, err)
		return
	}
	var msgReturn string
	switch e.Action {
	case "create":
		// Verify request fields
		if !environments.VerifyEnvFilters(e.Name, e.Icon, e.Type, e.Hostname) {
			apiErrorResponse(w, "invalid data", http.StatusBadRequest, nil)
			return
		}
		// Validate the optional client-supplied UUID strictly.
		//
		//   - utils.CheckUUID delegates to google/uuid Parse, accepting only
		//     canonical UUIDs. EnvUUIDFilter alone is `^[a-z0-9-]+$`, which
		//     would have happily accepted "-", "a", "deadbeef", etc.
		//   - ExistsByUUID (vs the polymorphic Exists) ensures a UUID-collision
		//     check cannot match against an existing env's NAME. The old
		//     Exists(e.UUID) leaked information across axes.
		if e.UUID != "" {
			if !utils.CheckUUID(e.UUID) {
				apiErrorResponse(w, "invalid uuid", http.StatusBadRequest, fmt.Errorf("rejected uuid %q", e.UUID))
				return
			}
			if h.Envs.ExistsByUUID(e.UUID) {
				apiErrorResponse(w, "uuid already in use", http.StatusConflict, fmt.Errorf("uuid %q collides", e.UUID))
				return
			}
		}
		// Check if environment already exists
		if !h.Envs.Exists(e.Name) {
			env := h.Envs.Empty(e.Name, e.Hostname)
			env.Icon = e.Icon
			env.Type = e.Type
			if e.UUID != "" {
				env.UUID = e.UUID
			}
			// Empty configuration
			env.Configuration = h.Envs.GenEmptyConfiguration(true)
			// Generate flags
			flags, err := h.Envs.GenerateFlags(env, "", "", h.OsqueryValues)
			if err != nil {
				apiErrorResponse(w, "error generating flags", http.StatusInternalServerError, err)
				return
			}
			env.Flags = flags
			// Create environment
			if err := h.Envs.Create(&env); err != nil {
				apiErrorResponse(w, "error creating environment", http.StatusInternalServerError, err)
				return
			}
			// Generate full permissions for the user creating the environment
			access := h.Users.GenEnvUserAccess([]string{env.UUID}, true, true, true, true)
			perms := h.Users.GenPermissions(ctx[ctxUser], "osctrl-api", access)
			if err := h.Users.CreatePermissions(perms); err != nil {
				apiErrorResponse(w, "error generating permissions", http.StatusInternalServerError, err)
				return
			}
			// Create a tag for this new environment
			if !h.Tags.Exists(env.Name) {
				if err := h.Tags.NewTag(
					env.Name,
					"Tag for environment "+env.Name,
					"",
					env.Icon,
					ctx[ctxUser],
					env.ID,
					false,
					tags.TagTypeEnv,
					""); err != nil {
					apiErrorResponse(w, "error generating tag", http.StatusInternalServerError, err)
					return
				}
			}
			msgReturn = "environment created successfully"
		} else {
			apiErrorResponse(w, "environment already exists", http.StatusBadRequest, fmt.Errorf("environment %s already exists", e.Name))
			return
		}
	case "delete":
		// Validate both name and UUID strictly, then verify they refer to
		// the SAME environment so the request can't authorise via one
		// env's UUID while targeting another env by name. The previous
		// shape (polymorphic Exists(e.UUID) → Delete(e.Name)) allowed
		// that authorisation/target split.
		if !environments.EnvNameFilter(e.Name) {
			apiErrorResponse(w, "invalid environment name", http.StatusBadRequest, nil)
			return
		}
		if e.UUID == "" {
			apiErrorResponse(w, "missing environment UUID", http.StatusBadRequest, nil)
			return
		}
		if !utils.CheckUUID(e.UUID) {
			apiErrorResponse(w, "invalid environment UUID", http.StatusBadRequest, nil)
			return
		}
		targetEnv, getErr := h.Envs.GetByUUID(e.UUID)
		if getErr != nil {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, fmt.Errorf("environment %s not found", e.UUID))
			return
		}
		if targetEnv.Name != e.Name {
			apiErrorResponse(w, "name does not match the environment with that UUID", http.StatusBadRequest, fmt.Errorf("uuid %s maps to name %q, body claims %q", e.UUID, targetEnv.Name, e.Name))
			return
		}
		if err := h.Envs.Delete(targetEnv.Name); err != nil {
			apiErrorResponse(w, "error deleting environment", http.StatusInternalServerError, err)
			return
		}
		msgReturn = "environment deleted successfully"
	case "edit":
		// Verify request fields
		if !environments.EnvUUIDFilter(e.UUID) {
			apiErrorResponse(w, "invalid environment UUID", http.StatusBadRequest, nil)
			return
		}
		if !environments.HostnameFilter(e.Hostname) {
			apiErrorResponse(w, "invalid hostname", http.StatusBadRequest, nil)
			return
		}
		if h.Envs.Exists(e.UUID) {
			if err := h.Envs.UpdateHostname(e.UUID, e.Hostname); err != nil {
				apiErrorResponse(w, "error updating hostname", http.StatusInternalServerError, err)
				return
			}
			msgReturn = "environment updated successfully"
		} else {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, fmt.Errorf("environment %s not found", e.UUID))
			return
		}
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, fmt.Errorf("invalid action %s", e.Action))
		return
	}
	// Return serialized response
	log.Debug().Msgf("Environment action %s completed: %s", e.Action, msgReturn)
	h.AuditLog.EnvAction(ctx[ctxUser], e.Action+" - "+e.Name, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// EnvConfigurationHandler - GET handler returning the assembled osquery
// configuration JSON for an environment. Returns the stored composed blob
// (options + schedule + packs + decorators + ATC). The composition is
// kept up to date by RefreshConfiguration, which fires from every parts
// mutation (UpdateOptions / UpdateSchedule / UpdatePacks / etc. in
// pkg/environments/osqueryconf.go), so reading the cached value is
// safe — the agents see the exact same blob.
//
// SECURITY: deliberately a pure read. The first cut of this handler
// called RefreshConfiguration on every GET, which turned the endpoint
// into a CSRF-via-GET shape and a hot-loop DB-write hazard when
// React-Query's stale refetch path hit it. The mutation path on the
// parts is the canonical place for the recompose.
func (h *HandlersApi) EnvConfigurationHandler(w http.ResponseWriter, r *http.Request) {
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
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiDataResponse{Data: env.Configuration})
}

// envCertUploadRequest is the body shape for EnvCertUploadHandler. The PEM
// is sent base64-encoded so the upload survives clients that mangle raw
// newlines (curl --data, browser fetch with a plain string body, etc.).
type envCertUploadRequest struct {
	CertificateB64 string `json:"certificate_b64"`
}

// EnvCertUploadHandler - POST handler to upload the enrollment certificate
// for an environment. Body: { "certificate_b64": "<base64 PEM>" }. The PEM
// must parse as one or more CERTIFICATE blocks and the leaf must be a real
// x509 cert — we don't accept "looks like base64 of something." Legacy
// admin's equivalent path skipped this validation; the SPA target gets it
// so a typo'd paste fails fast instead of breaking enrollment downloads.
func (h *HandlersApi) EnvCertUploadHandler(w http.ResponseWriter, r *http.Request) {
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
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return
	}
	var req envCertUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	if req.CertificateB64 == "" {
		apiErrorResponse(w, "empty certificate", http.StatusBadRequest, nil)
		return
	}
	pemBytes, err := base64.StdEncoding.DecodeString(req.CertificateB64)
	if err != nil {
		apiErrorResponse(w, "error decoding certificate", http.StatusBadRequest, err)
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		apiErrorResponse(w, "invalid PEM: no CERTIFICATE block", http.StatusBadRequest, nil)
		return
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		apiErrorResponse(w, "invalid x509 certificate", http.StatusBadRequest, err)
		return
	}
	if err := h.Envs.UpdateCertificate(env.UUID, string(pemBytes)); err != nil {
		apiErrorResponse(w, "error saving certificate", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Certificate updated for environment %s", env.Name)
	h.AuditLog.EnvAction(ctx[ctxUser], "upload certificate for environment "+env.Name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "certificate uploaded successfully"})
}

// substitutePlatformPaths fills the __SECRET_FILE__ / __CERT_FILE__ placeholders
// in the env.Flags template with the canonical install paths for a given OS.
// This is the same substitution legacy admin's download path performs (see
// cmd/admin/handlers/utils.go generateFlags); centralising it here keeps the
// API's per-OS flag downloads producing the exact bytes operators expect to
// drop into /etc/osquery/osctrl-{env}.flags (or the platform equivalent).
//
// sep is the path separator the OS uses ("/" for everything except Windows).
func substitutePlatformPaths(flags, envName, dir, sep string) string {
	secretPath := dir + sep + "osctrl-" + envName + ".secret"
	certPath := dir + sep + "osctrl-" + envName + ".crt"
	out := strings.Replace(flags, "__SECRET_FILE__", secretPath, 1)
	out = strings.Replace(out, "__CERT_FILE__", certPath, 1)
	return out
}
