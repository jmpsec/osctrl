package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const tokenRefreshDefaultHours = 24

// GetUserPermissionsHandler - GET /api/v1/users/{username}/permissions
//
// Returns the target user's current permission map: env UUID →
// {user, query, carve, admin}. Envs with no permission rows are
// omitted (treated as "no access" by the SPA). Requires super-admin
// (AdminLevel, NoEnvironment).
//
// Used by the Permissions modal to prefill checkboxes with the
// user's existing access for the selected env, so the operator
// sees current state before making changes — no more accidentally
// overwriting (user:true, query:true) by re-saving the modal's
// default of (user:true, query:false).
// @Summary Get user permissions
// @Description Returns per-environment permissions for a user.
// @Tags users
// @Produce json
// @Param username path string true "Username"
// @Success 200 {object} types.GetPermissionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/permissions [get]
func (h *HandlersApi) GetUserPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	username := r.PathValue("username")
	if username == "" {
		apiErrorResponse(w, "missing username", http.StatusBadRequest, nil)
		return
	}
	if !h.Users.Exists(username) {
		apiErrorResponse(w, "user not found", http.StatusNotFound, nil)
		return
	}
	access, err := h.Users.GetAccess(username)
	if err != nil {
		apiErrorResponse(w, "error getting permissions", http.StatusInternalServerError, err)
		return
	}
	out := make(map[string]types.EnvAccessView, len(access))
	for envUUID, ea := range access {
		out[envUUID] = types.EnvAccessView{
			User:  ea.User,
			Query: ea.Query,
			Carve: ea.Carve,
			Admin: ea.Admin,
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.GetPermissionsResponse{
		Username:    username,
		Permissions: out,
	})
}

// SetUserPermissionsHandler - POST /api/v1/users/{username}/permissions
//
// Body: { env_uuid, access: { user, query, carve, admin } }. Replaces the
// target user's per-env access rows. Returns 200 with the new EnvAccess.
// Requires super-admin (AdminLevel, NoEnvironment) — env-scoped admins can
// not grant permissions for their environment from this endpoint.
// @Summary Set user permissions
// @Description Sets per-environment permissions for a user.
// @Tags users
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Param request body types.SetPermissionsRequest true "Request body"
// @Success 200 {object} types.EnvAccessView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/permissions [post]
func (h *HandlersApi) SetUserPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	username := r.PathValue("username")
	if username == "" {
		apiErrorResponse(w, "missing username", http.StatusBadRequest, nil)
		return
	}
	if !h.Users.Exists(username) {
		apiErrorResponse(w, "user not found", http.StatusNotFound, nil)
		return
	}

	var body types.SetPermissionsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	body.EnvUUID = strings.TrimSpace(body.EnvUUID)
	if body.EnvUUID == "" {
		apiErrorResponse(w, "env_uuid is required", http.StatusBadRequest, nil)
		return
	}
	if _, err := h.Envs.GetByUUID(body.EnvUUID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return
	}

	access := users.EnvAccess{
		User:  body.Access.User,
		Query: body.Access.Query,
		Carve: body.Access.Carve,
		Admin: body.Access.Admin,
	}

	// Lockout guards. A super-admin cannot:
	//   1. Self-demote — granting yourself a strict downgrade via this
	//      endpoint risks locking yourself out of further permission
	//      changes if no other super-admin exists. Force the operator
	//      to go through another super-admin.
	//   2. Demote the LAST super-admin under any path. If admin=false
	//      and the target is the only AdminUser.Admin=true row, the
	//      system has no remaining super-admin and no one can manage
	//      users / envs / settings. Refuse with 409.
	if username == ctx[ctxUser] && !access.Admin {
		apiErrorResponse(w, "super-admins cannot self-demote via this endpoint", http.StatusForbidden, nil)
		return
	}
	if !access.Admin && h.Users.IsAdmin(username) {
		count, cerr := h.Users.CountAdmins()
		if cerr != nil {
			apiErrorResponse(w, "error checking admin count", http.StatusInternalServerError, cerr)
			return
		}
		if count <= 1 {
			apiErrorResponse(w, "refusing to demote the last super-admin", http.StatusConflict, fmt.Errorf("only %d admin user(s) remain", count))
			return
		}
	}

	if err := h.Users.ChangeAccess(username, body.EnvUUID, access); err != nil {
		apiErrorResponse(w, "error setting permissions", http.StatusInternalServerError, err)
		return
	}

	h.AuditLog.Permissions(ctx[ctxUser],
		fmt.Sprintf("set %s on env=%s u=%v q=%v c=%v a=%v",
			username, body.EnvUUID, access.User, access.Query, access.Carve, access.Admin),
		strings.Split(r.RemoteAddr, ":")[0], 0)
	log.Debug().Msgf("permissions updated for user %s on env %s", username, body.EnvUUID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, body.Access)
}

// SetUserPermissionsAllHandler - POST /api/v1/users/{username}/permissions/all
//
// Bulk variant of SetUserPermissionsHandler: applies the same EnvAccess
// shape to every environment that exists at request time. Body:
// { access: { user, query, carve, admin } }. Returns
// { updated, total, access } on success.
//
// Same authn/authz posture as the per-env handler: requires super-admin
// (AdminLevel, NoEnvironment). Same lockout guards:
//
//   - Super-admins cannot self-demote via this endpoint.
//   - The last super-admin cannot be demoted under any path.
//
// "All current envs" semantics: enumeration happens server-side at
// request time. Envs created LATER do not inherit; the operator
// re-applies as needed. See SetPermissionsAllRequest godoc.
// @Summary Set all user permissions
// @Description Sets permissions across all environments for a user.
// @Tags users
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Param request body types.SetPermissionsAllRequest true "Request body"
// @Success 200 {object} types.SetPermissionsAllResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/permissions/all [post]
func (h *HandlersApi) SetUserPermissionsAllHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	username := r.PathValue("username")
	if username == "" {
		apiErrorResponse(w, "missing username", http.StatusBadRequest, nil)
		return
	}
	if !h.Users.Exists(username) {
		apiErrorResponse(w, "user not found", http.StatusNotFound, nil)
		return
	}

	var body types.SetPermissionsAllRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}

	access := users.EnvAccess{
		User:  body.Access.User,
		Query: body.Access.Query,
		Carve: body.Access.Carve,
		Admin: body.Access.Admin,
	}

	// Lockout guards — identical to SetUserPermissionsHandler.
	// Without these, the bulk endpoint would be a privilege-
	// escalation hole (an operator could write !admin to ALL envs
	// and lock the last super-admin out everywhere in a single
	// call).
	if username == ctx[ctxUser] && !access.Admin {
		apiErrorResponse(w, "super-admins cannot self-demote via this endpoint", http.StatusForbidden, nil)
		return
	}
	if !access.Admin && h.Users.IsAdmin(username) {
		count, cerr := h.Users.CountAdmins()
		if cerr != nil {
			apiErrorResponse(w, "error checking admin count", http.StatusInternalServerError, cerr)
			return
		}
		if count <= 1 {
			apiErrorResponse(w, "refusing to demote the last super-admin", http.StatusConflict, fmt.Errorf("only %d admin user(s) remain", count))
			return
		}
	}

	envs, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "error enumerating environments", http.StatusInternalServerError, err)
		return
	}
	uuids := make([]string, 0, len(envs))
	for _, e := range envs {
		uuids = append(uuids, e.UUID)
	}

	updated, err := h.Users.ChangeAccessAll(username, uuids, access)
	if err != nil {
		// ChangeAccessAll returns a partial count on error. We
		// surface that to the operator so they know how many envs
		// succeeded before the abort. The HTTP status still has to
		// be 500 — the whole request did not complete.
		apiErrorResponse(w,
			fmt.Sprintf("error setting permissions (%d of %d envs updated before failure)", updated, len(uuids)),
			http.StatusInternalServerError, err)
		return
	}

	h.AuditLog.Permissions(ctx[ctxUser],
		fmt.Sprintf("set %s on ALL %d envs u=%v q=%v c=%v a=%v",
			username, updated, access.User, access.Query, access.Carve, access.Admin),
		strings.Split(r.RemoteAddr, ":")[0], 0)
	log.Debug().Msgf("permissions updated for user %s on all %d envs", username, updated)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.SetPermissionsAllResponse{
		Updated: updated,
		Total:   len(uuids),
		Access:  body.Access,
	})
}

// RefreshUserTokenHandler - POST /api/v1/users/{username}/token/refresh
//
// Generates a new JWT for the target user, persists it as the user's
// APIToken (invalidating the previous token), and returns the new token +
// expiry. Requires super-admin OR the request author asking for their own
// token. Audit-logged on success.
// @Summary Refresh user token
// @Description Refreshes an API token for a user.
// @Tags users
// @Accept json
// @Produce json
// @Param username path string true "Username"
// @Success 200 {object} types.TokenResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/token/refresh [post]
func (h *HandlersApi) RefreshUserTokenHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	username := r.PathValue("username")
	if username == "" {
		apiErrorResponse(w, "missing username", http.StatusBadRequest, nil)
		return
	}
	requester := ctx[ctxUser]
	isSelf := username == requester
	if !isSelf && !h.Users.CheckPermissions(requester, users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to refresh token for %s by %s", username, requester))
		return
	}
	if !h.Users.Exists(username) {
		apiErrorResponse(w, "user not found", http.StatusNotFound, nil)
		return
	}

	token, expires, err := h.Users.CreateToken(username, h.ServiceName, tokenRefreshDefaultHours)
	if err != nil {
		apiErrorResponse(w, "error creating token", http.StatusInternalServerError, err)
		return
	}
	if err := h.Users.UpdateToken(username, token, expires); err != nil {
		apiErrorResponse(w, "error persisting token", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.NewToken(username, strings.Split(r.RemoteAddr, ":")[0])
	log.Debug().Msgf("refreshed API token for %s (requested by %s)", username, requester)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.TokenResponse{Token: token, Expires: expires})
}

// DeleteUserTokenHandler - DELETE /api/v1/users/{username}/token
//
// Clears the user's APIToken so any existing JWT for them stops working.
// Requires super-admin OR the user themselves.
// @Summary Delete user token
// @Description Deletes an API token for a user.
// @Tags users
// @Produce json
// @Param username path string true "Username"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/token [delete]
func (h *HandlersApi) DeleteUserTokenHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	username := r.PathValue("username")
	if username == "" {
		apiErrorResponse(w, "missing username", http.StatusBadRequest, nil)
		return
	}
	requester := ctx[ctxUser]
	isSelf := username == requester
	if !isSelf && !h.Users.CheckPermissions(requester, users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to delete token for %s by %s", username, requester))
		return
	}
	if err := h.Users.ClearToken(username); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "user not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error clearing token", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.UserAction(requester, "deleted token for "+username, strings.Split(r.RemoteAddr, ":")[0])
	log.Debug().Msgf("deleted API token for %s (requested by %s)", username, requester)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "token deleted"})
}

// MeHandler - GET /api/v1/users/me
//
// Returns the currently authenticated user's profile (sans password hash
// and API token). Useful for the SPA's Profile page.
// @Summary Get current user
// @Description Returns the currently authenticated user profile.
// @Tags users
// @Produce json
// @Success 200 {object} types.UserMeResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/me [get]
func (h *HandlersApi) MeHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	requester := ctx[ctxUser]
	user, err := h.Users.Get(requester)
	if err != nil {
		apiErrorResponse(w, "error getting user", http.StatusInternalServerError, err)
		return
	}
	// Pull the user's permission map so the SPA can hide nav items
	// the operator has no access to. GetAccess errors are non-fatal
	// — we still return the profile; the SPA falls back to "no
	// per-env access known yet" and shows nothing env-scoped, which
	// is the safe default.
	perms := make(map[string]types.EnvAccessView)
	if access, gerr := h.Users.GetAccess(requester); gerr == nil {
		for env, ea := range access {
			perms[env] = types.EnvAccessView{
				User:  ea.User,
				Query: ea.Query,
				Carve: ea.Carve,
				Admin: ea.Admin,
			}
		}
	}
	resp := types.UserMeResponse{
		Username:    user.Username,
		Email:       user.Email,
		Fullname:    user.Fullname,
		Admin:       user.Admin,
		Service:     user.Service,
		UUID:        user.UUID,
		TokenExpire: user.TokenExpire,
		LastAccess:  user.LastAccess,
		Permissions: perms,
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// MePatchHandler - PATCH /api/v1/users/me
//
// Updates email and/or fullname for the currently authenticated user. Sends
// each empty field through unchanged. Returns the updated profile.
// @Summary Update current user
// @Description Updates the current user's profile fields.
// @Tags users
// @Accept json
// @Produce json
// @Param request body types.UserMePatchRequest true "Request body"
// @Success 200 {object} types.UserMeResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/me [patch]
func (h *HandlersApi) MePatchHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	requester := ctx[ctxUser]
	var body types.UserMePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing PATCH body", http.StatusBadRequest, err)
		return
	}
	body.Email = strings.TrimSpace(body.Email)
	body.Fullname = strings.TrimSpace(body.Fullname)

	if body.Email != "" {
		if err := h.Users.ChangeEmail(requester, body.Email); err != nil {
			apiErrorResponse(w, "error updating email", http.StatusInternalServerError, err)
			return
		}
	}
	if body.Fullname != "" {
		if err := h.Users.ChangeFullname(requester, body.Fullname); err != nil {
			apiErrorResponse(w, "error updating fullname", http.StatusInternalServerError, err)
			return
		}
	}

	user, err := h.Users.Get(requester)
	if err != nil {
		apiErrorResponse(w, "error fetching updated user", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.UserAction(requester, "updated own profile", strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.UserMeResponse{
		Username:    user.Username,
		Email:       user.Email,
		Fullname:    user.Fullname,
		Admin:       user.Admin,
		Service:     user.Service,
		UUID:        user.UUID,
		TokenExpire: user.TokenExpire,
		LastAccess:  user.LastAccess,
	})
}

// MePasswordHandler - POST /api/v1/users/me/password
//
// Changes the currently authenticated user's password. Verifies the
// current password (bcrypt) before persisting the new hash.
// @Summary Change current user password
// @Description Changes the current user's password.
// @Tags users
// @Accept json
// @Produce json
// @Param request body types.PasswordChangeRequest true "Request body"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/users/me/password [post]
func (h *HandlersApi) MePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	requester := ctx[ctxUser]

	var body types.PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	if body.CurrentPassword == "" || body.NewPassword == "" {
		apiErrorResponse(w, "current_password and new_password are required", http.StatusBadRequest, nil)
		return
	}
	if len(body.NewPassword) < 8 {
		apiErrorResponse(w, "new_password must be at least 8 characters", http.StatusBadRequest, nil)
		return
	}
	if ok, _ := h.Users.CheckLoginCredentials(requester, body.CurrentPassword); !ok {
		apiErrorResponse(w, "current password is incorrect", http.StatusForbidden, nil)
		return
	}
	if err := h.Users.ChangePassword(requester, body.NewPassword); err != nil {
		apiErrorResponse(w, "error changing password", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.UserAction(requester, "changed own password", strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "password changed"})
}
