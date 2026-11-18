package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/scim"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// SCIM requests carry at most a group's full member list.
const scimMaxBody = 2 << 20

const scimJSON = "application/scim+json"

// SCIMListResponse is a page of SCIM resources.
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int64    `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

// SCIMErrorResponse is a SCIM error.
type SCIMErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// SCIMStatusResponse says whether SCIM provisioning is on.
type SCIMStatusResponse struct {
	// Available is false when Santa is disabled; SCIM only feeds Santa group tags.
	Available bool `json:"available"`
	Enabled   bool `json:"enabled"`
	// TokenCreatedAt is when the current token was made.
	TokenCreatedAt *time.Time `json:"token_created_at,omitempty"`
}

// SCIMTokenResponse carries a new SCIM token, shown once.
type SCIMTokenResponse struct {
	Token string `json:"token"`
}

// UserGroupsResponse is the IdP groups stored for a user.
type UserGroupsResponse struct {
	Groups    []string   `json:"groups"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// SCIM is true when SCIM provisions the user, so SSO logins leave the
	// groups alone.
	SCIM bool `json:"scim"`
}

func scimFail(w http.ResponseWriter, status int, scimType, detail string) {
	utils.HTTPResponse(w, scimJSON, status, SCIMErrorResponse{
		Schemas: []string{scim.SchemaError}, Status: strconv.Itoa(status), ScimType: scimType, Detail: detail,
	})
}

func scimError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scim.ErrNotFound):
		scimFail(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, scim.ErrConflict):
		scimFail(w, http.StatusConflict, "uniqueness", "userName already exists")
	case errors.Is(err, scim.ErrFilter):
		scimFail(w, http.StatusBadRequest, "invalidFilter", `only "attribute eq \"value\"" filters are supported`)
	case errors.Is(err, scim.ErrInvalid):
		scimFail(w, http.StatusBadRequest, "invalidValue", "invalid value")
	default:
		log.Err(err).Msg("scim: request failed")
		scimFail(w, http.StatusInternalServerError, "", "internal error")
	}
}

func scimDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		scimFail(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return false
	}
	return true
}

// SCIMAuth admits requests that present the SCIM bearer token. It is separate
// from user sessions: no cookies, so no CSRF, and no osctrl user behind it.
func (h *HandlersApi) SCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if h.SCIM == nil || !ok || !h.SCIM.CheckToken(strings.TrimSpace(tok)) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="osctrl-scim"`)
			scimFail(w, http.StatusUnauthorized, "", "missing or invalid SCIM token")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, scimMaxBody)
		next.ServeHTTP(w, r)
	})
}

// scimApplied audits a change and rewrites the Santa groups of the users it
// touched. A failure answers 500 so the identity provider retries; the
// rewrite is idempotent.
func (h *HandlersApi) scimApplied(w http.ResponseWriter, r *http.Request, action string, names []string) bool {
	h.AuditLog.UserAction("scim", "scim: "+action, utils.GetIP(r))
	for _, n := range names {
		groups, err := h.SCIM.Groups(n)
		if err == nil && h.Santa != nil {
			err = h.Santa.SetUserGroups(n, groups)
		}
		if err != nil {
			scimError(w, fmt.Errorf("syncing groups of %s: %w", n, err))
			return false
		}
	}
	return true
}

// scimPage reads filter, startIndex and count.
func scimPage(r *http.Request) (scim.Filter, int, int, error) {
	q := r.URL.Query()
	f, err := scim.ParseFilter(q.Get("filter"))
	start, count := 1, 100
	if v, e := strconv.Atoi(q.Get("startIndex")); e == nil && v > 1 {
		start = v
	}
	if v, e := strconv.Atoi(q.Get("count")); e == nil && v >= 0 {
		count = min(v, scim.MaxCount)
	}
	return f, start, count, err
}

func scimList[T any](w http.ResponseWriter, items []T, total int64, start int) {
	utils.HTTPResponse(w, scimJSON, http.StatusOK, SCIMListResponse{
		Schemas: []string{scim.SchemaList}, TotalResults: total, StartIndex: start, ItemsPerPage: len(items), Resources: items,
	})
}

// SCIMServiceProviderConfigHandler — GET /api/v1/scim/v2/ServiceProviderConfig
// @Summary SCIM service provider configuration
// @Description What the SCIM endpoint supports. Authenticated with the SCIM bearer token.
// @Tags scim
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 401 {object} SCIMErrorResponse
// @Router /api/v1/scim/v2/ServiceProviderConfig [get]
func (h *HandlersApi) SCIMServiceProviderConfigHandler(w http.ResponseWriter, r *http.Request) {
	no := map[string]bool{"supported": false}
	utils.HTTPResponse(w, scimJSON, http.StatusOK, map[string]any{
		"schemas":        []string{scim.SchemaConfig},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scim.MaxCount},
		"changePassword": no,
		"sort":           no,
		"etag":           no,
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token", "description": "The SCIM token from osctrl", "primary": true,
		}},
	})
}

// SCIMUsersHandler — GET and POST /api/v1/scim/v2/Users
// @Summary List or provision SCIM users
// @Description GET supports `filter=userName eq "x"` (also externalId, id), startIndex and count. POST provisions a user. Authenticated with the SCIM bearer token.
// @Tags scim
// @Accept json
// @Produce json
// @Param filter query string false "attribute eq \"value\""
// @Param startIndex query int false "1-based index"
// @Param count query int false "Page size, at most 200"
// @Param body body scim.UserResource false "User (POST)"
// @Success 200 {object} SCIMListResponse
// @Success 201 {object} scim.UserResource
// @Failure 400 {object} SCIMErrorResponse
// @Failure 401 {object} SCIMErrorResponse
// @Failure 409 {object} SCIMErrorResponse
// @Router /api/v1/scim/v2/Users [get]
// @Router /api/v1/scim/v2/Users [post]
func (h *HandlersApi) SCIMUsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in scim.UserResource
		if !scimDecode(w, r, &in) {
			return
		}
		u, names, err := h.SCIM.CreateUser(in)
		if err != nil {
			scimError(w, err)
			return
		}
		if h.scimApplied(w, r, "create user "+u.UserName, names) {
			utils.HTTPResponse(w, scimJSON, http.StatusCreated, u)
		}
		return
	}
	f, start, count, err := scimPage(r)
	if err != nil {
		scimError(w, err)
		return
	}
	us, total, err := h.SCIM.ListUsers(f, start, count)
	if err != nil {
		scimError(w, err)
		return
	}
	scimList(w, us, total, start)
}

// SCIMUserHandler — GET, PUT, PATCH and DELETE /api/v1/scim/v2/Users/{id}
// @Summary Read, replace, patch or delete a SCIM user
// @Description PATCH sets active, userName and externalId; other attributes are accepted and ignored. A user that is inactive or deleted has no groups. Authenticated with the SCIM bearer token.
// @Tags scim
// @Accept json
// @Produce json
// @Param id path string true "SCIM user ID"
// @Success 200 {object} scim.UserResource
// @Success 204
// @Failure 400 {object} SCIMErrorResponse
// @Failure 401 {object} SCIMErrorResponse
// @Failure 404 {object} SCIMErrorResponse
// @Failure 409 {object} SCIMErrorResponse
// @Router /api/v1/scim/v2/Users/{id} [get]
// @Router /api/v1/scim/v2/Users/{id} [put]
// @Router /api/v1/scim/v2/Users/{id} [patch]
// @Router /api/v1/scim/v2/Users/{id} [delete]
func (h *HandlersApi) SCIMUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var (
		u     scim.UserResource
		names []string
		err   error
	)
	switch r.Method {
	case http.MethodGet:
		if u, err = h.SCIM.GetUser(id); err != nil {
			scimError(w, err)
			return
		}
		utils.HTTPResponse(w, scimJSON, http.StatusOK, u)
		return
	case http.MethodDelete:
		if u, err = h.SCIM.GetUser(id); err == nil {
			names, err = h.SCIM.DeleteUser(id)
		}
		if err != nil {
			scimError(w, err)
			return
		}
		if h.scimApplied(w, r, "delete user "+u.UserName, names) {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	case http.MethodPut:
		var in scim.UserResource
		if !scimDecode(w, r, &in) {
			return
		}
		u, names, err = h.SCIM.ReplaceUser(id, in)
	default:
		var in scim.PatchRequest
		if !scimDecode(w, r, &in) {
			return
		}
		u, names, err = h.SCIM.PatchUser(id, in.Operations)
	}
	if err != nil {
		scimError(w, err)
		return
	}
	if h.scimApplied(w, r, fmt.Sprintf("update user %s active=%t", u.UserName, *u.Active), names) {
		utils.HTTPResponse(w, scimJSON, http.StatusOK, u)
	}
}

// SCIMGroupsHandler — GET and POST /api/v1/scim/v2/Groups
// @Summary List or provision SCIM groups
// @Description GET supports `filter=displayName eq "x"` (also externalId, id), startIndex, count and excludedAttributes=members. POST provisions a group; every member must be a provisioned user. Authenticated with the SCIM bearer token.
// @Tags scim
// @Accept json
// @Produce json
// @Param filter query string false "attribute eq \"value\""
// @Param startIndex query int false "1-based index"
// @Param count query int false "Page size, at most 200"
// @Param excludedAttributes query string false "members to leave members out"
// @Param body body scim.GroupResource false "Group (POST)"
// @Success 200 {object} SCIMListResponse
// @Success 201 {object} scim.GroupResource
// @Failure 400 {object} SCIMErrorResponse
// @Failure 401 {object} SCIMErrorResponse
// @Router /api/v1/scim/v2/Groups [get]
// @Router /api/v1/scim/v2/Groups [post]
func (h *HandlersApi) SCIMGroupsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var in scim.GroupResource
		if !scimDecode(w, r, &in) {
			return
		}
		g, names, err := h.SCIM.CreateGroup(in)
		if err != nil {
			scimError(w, err)
			return
		}
		if h.scimApplied(w, r, fmt.Sprintf("create group %s members=%d", g.DisplayName, len(g.Members)), names) {
			utils.HTTPResponse(w, scimJSON, http.StatusCreated, g)
		}
		return
	}
	f, start, count, err := scimPage(r)
	if err != nil {
		scimError(w, err)
		return
	}
	gs, total, err := h.SCIM.ListGroups(f, start, count, scimMembers(r))
	if err != nil {
		scimError(w, err)
		return
	}
	scimList(w, gs, total, start)
}

// scimMembers is false when the request excludes the members attribute.
func scimMembers(r *http.Request) bool {
	return !slices.ContainsFunc(strings.Split(r.URL.Query().Get("excludedAttributes"), ","), func(a string) bool {
		return strings.EqualFold(strings.TrimSpace(a), "members")
	})
}

// SCIMGroupHandler — GET, PUT, PATCH and DELETE /api/v1/scim/v2/Groups/{id}
// @Summary Read, replace, patch or delete a SCIM group
// @Description PATCH adds, removes and replaces members (including `members[value eq "id"]` paths) and sets displayName and externalId. Authenticated with the SCIM bearer token.
// @Tags scim
// @Accept json
// @Produce json
// @Param id path string true "SCIM group ID"
// @Success 200 {object} scim.GroupResource
// @Success 204
// @Failure 400 {object} SCIMErrorResponse
// @Failure 401 {object} SCIMErrorResponse
// @Failure 404 {object} SCIMErrorResponse
// @Router /api/v1/scim/v2/Groups/{id} [get]
// @Router /api/v1/scim/v2/Groups/{id} [put]
// @Router /api/v1/scim/v2/Groups/{id} [patch]
// @Router /api/v1/scim/v2/Groups/{id} [delete]
func (h *HandlersApi) SCIMGroupHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var (
		g     scim.GroupResource
		names []string
		err   error
	)
	switch r.Method {
	case http.MethodGet:
		if g, err = h.SCIM.GetGroup(id, scimMembers(r)); err != nil {
			scimError(w, err)
			return
		}
		utils.HTTPResponse(w, scimJSON, http.StatusOK, g)
		return
	case http.MethodDelete:
		if g, err = h.SCIM.GetGroup(id, false); err == nil {
			names, err = h.SCIM.DeleteGroup(id)
		}
		if err != nil {
			scimError(w, err)
			return
		}
		if h.scimApplied(w, r, "delete group "+g.DisplayName, names) {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	case http.MethodPut:
		var in scim.GroupResource
		if !scimDecode(w, r, &in) {
			return
		}
		g, names, err = h.SCIM.ReplaceGroup(id, in)
	default:
		var in scim.PatchRequest
		if !scimDecode(w, r, &in) {
			return
		}
		g, names, err = h.SCIM.PatchGroup(id, in.Operations)
	}
	if err != nil {
		scimError(w, err)
		return
	}
	if h.scimApplied(w, r, fmt.Sprintf("update group %s members=%d", g.DisplayName, len(g.Members)), names) {
		utils.HTTPResponse(w, scimJSON, http.StatusOK, g)
	}
}

// scimSuperuser requires a superuser for SCIM token management.
func (h *HandlersApi) scimSuperuser(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return "", false
	}
	user := ctxVal.(ContextValue)[ctxUser]
	if !h.isSuperAdmin(r, user) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return "", false
	}
	return user, true
}

// SCIMStatusHandler — GET /api/v1/scim
// @Summary SCIM provisioning status
// @Description Requires superuser.
// @Tags scim
// @Produce json
// @Success 200 {object} SCIMStatusResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/scim [get]
func (h *HandlersApi) SCIMStatusHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.scimSuperuser(w, r); !ok {
		return
	}
	var out SCIMStatusResponse
	if h.SCIM != nil {
		out.Available = true
		created, err := h.SCIM.TokenCreated()
		if err != nil {
			apiErrorResponse(w, "error reading SCIM status", http.StatusInternalServerError, err)
			return
		}
		if !created.IsZero() {
			out.Enabled, out.TokenCreatedAt = true, &created
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// SCIMTokenHandler — POST and DELETE /api/v1/scim/token
// @Summary Rotate or remove the SCIM token
// @Description POST makes a new token, which turns SCIM on and replaces any previous token; it is shown once. DELETE removes it, which turns SCIM off. Requires superuser.
// @Tags scim
// @Produce json
// @Success 200 {object} SCIMTokenResponse
// @Success 204
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/scim/token [post]
// @Router /api/v1/scim/token [delete]
func (h *HandlersApi) SCIMTokenHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.scimSuperuser(w, r)
	if !ok {
		return
	}
	if h.SCIM == nil {
		apiErrorResponse(w, "SCIM needs Santa enabled", http.StatusServiceUnavailable, nil)
		return
	}
	if r.Method == http.MethodDelete {
		if err := h.SCIM.DisableToken(); err != nil {
			apiErrorResponse(w, "error removing SCIM token", http.StatusInternalServerError, err)
			return
		}
		h.AuditLog.UserAction(user, "scim: remove token", utils.GetIP(r))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token, err := h.SCIM.RotateToken()
	if err != nil {
		apiErrorResponse(w, "error rotating SCIM token", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.UserAction(user, "scim: rotate token", utils.GetIP(r))
	w.Header().Set("Cache-Control", "no-store")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, SCIMTokenResponse{Token: token})
}

// UserGroupsHandler — GET /api/v1/users/{username}/groups
// @Summary IdP groups stored for a user
// @Description The groups Santa group tags use, from the user's last SSO login or from SCIM. Requires the same access as reading the user.
// @Tags users
// @Produce json
// @Param username path string true "Username"
// @Success 200 {object} UserGroupsResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/users/{username}/groups [get]
func (h *HandlersApi) UserGroupsHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	user := ctxVal.(ContextValue)[ctxUser]
	if !h.Users.HasRoleContext(r.Context(), user, users.RoleReadOnly) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return
	}
	username := r.PathValue("username")
	out := UserGroupsResponse{Groups: []string{}}
	if h.Santa != nil {
		ug, err := h.Santa.UserGroupsOf(username)
		if err != nil {
			apiErrorResponse(w, "error getting groups", http.StatusInternalServerError, err)
			return
		}
		out.Groups = ug.Groups
		if !ug.UpdatedAt.IsZero() {
			out.UpdatedAt = &ug.UpdatedAt
		}
	}
	if h.SCIM != nil {
		managed, err := h.SCIM.Managed(username)
		if err != nil {
			apiErrorResponse(w, "error getting groups", http.StatusInternalServerError, err)
			return
		}
		out.SCIM = managed
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}
