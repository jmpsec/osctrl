package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

const groupMappingsMaxBody = 1 << 20

// GroupMappingsResponse is the IdP group mappings, and on a change how many
// grants and revokes it made.
type GroupMappingsResponse struct {
	Mappings []users.GroupMapping `json:"mappings"`
	Changes  int                  `json:"changes"`
}

// syncGroupAccess applies the group mappings to username and audits every
// grant and revoke as actor.
func (h *HandlersApi) syncGroupAccess(actor, ip, username string, groups []string) error {
	changes, err := h.Users.SyncGroupAccess(username, groups)
	for _, c := range changes {
		h.AuditLog.UserAction(actor, "idp groups: "+c.String(), ip)
	}
	return err
}

// recordSSOGroups keeps the IdP groups of an SSO login: for Santa group tags
// and for the group mappings. nil groups mean the provider has no groups
// claim, so nothing changes; neither does it for a user SCIM provisions,
// whose groups come from SCIM. A failure is logged and never blocks the login.
func (h *HandlersApi) recordSSOGroups(username string, groups []string, ip string) {
	if groups == nil {
		return
	}
	if h.SCIM != nil {
		managed, err := h.SCIM.Managed(username)
		if err != nil {
			log.Err(err).Str("username", username).Msg("error checking SCIM")
			return
		}
		if managed {
			return
		}
	}
	h.santaRecordGroups(username, groups)
	if err := h.syncGroupAccess(username, ip, username, groups); err != nil {
		log.Err(err).Str("username", username).Msg("error applying IdP group mappings")
	}
}

// GroupMappingsHandler — GET /api/v1/group-mappings
// @Summary List the IdP group mappings
// @Description Requires the user management role. Each mapping gives the members of an IdP group (display name, from SCIM or the groups claim of an SSO login) global roles and environment permissions.
// @Tags users
// @Produce json
// @Success 200 {object} GroupMappingsResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/group-mappings [get]
func (h *HandlersApi) GroupMappingsHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ContextKey(contextAPI)).(ContextValue)[ctxUser]
	if !h.Users.HasRoleContext(r.Context(), user, users.RoleUserManagement) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return
	}
	ms, err := h.Users.GroupMappings()
	if err != nil {
		apiErrorResponse(w, "error getting group mappings", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, GroupMappingsResponse{Mappings: ms})
}

// GroupMappingsPutHandler — PUT /api/v1/group-mappings
// @Summary Replace the IdP group mappings
// @Description Requires superuser. Replaces every mapping, then applies them to the users whose IdP groups osctrl has seen: SCIM-provisioned users and SSO users after a login with a groups claim. Roles are user_admin, env_manager, read_only_admin and alert_admin; superuser is never granted. Environment tiers are standard or full. A mapping only grants access the user does not hold, and only revokes access a mapping granted; access granted by hand is never changed. Every grant and revoke is audited.
// @Tags users
// @Accept json
// @Produce json
// @Param body body []users.GroupMapping true "Mappings"
// @Success 200 {object} GroupMappingsResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/group-mappings [put]
func (h *HandlersApi) GroupMappingsPutHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ContextKey(contextAPI)).(ContextValue)[ctxUser]
	if !h.Users.HasRoleContext(r.Context(), user, users.RoleSuperuser) {
		apiErrorResponse(w, "changing the group mappings requires superuser", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, groupMappingsMaxBody))
	var ms []users.GroupMapping
	if err == nil {
		err = json.Unmarshal(body, &ms)
	}
	if err != nil {
		apiErrorResponse(w, "invalid request: expected a JSON list of mappings", http.StatusBadRequest, err)
		return
	}
	if err := users.ValidateGroupMappings(ms, h.Envs.ExistsByUUID); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, users.ErrInvalidGroupMapping) {
			status = http.StatusBadRequest
		}
		apiErrorResponse(w, err.Error(), status, nil)
		return
	}
	if err := h.Users.SetGroupMappings(ms, user); err != nil {
		apiErrorResponse(w, "error saving group mappings", http.StatusInternalServerError, err)
		return
	}
	groups := make([]string, 0, len(ms))
	for _, m := range ms {
		groups = append(groups, m.Group)
	}
	ip := utils.GetIP(r)
	h.AuditLog.UserAction(user, "users: set group mappings groups="+strings.Join(groups, ","), ip)
	seen, err := h.Users.GroupAccessUsers()
	if err != nil {
		apiErrorResponse(w, "mappings saved, error listing users to apply them to", http.StatusInternalServerError, err)
		return
	}
	n := 0
	for _, u := range seen {
		changes, err := h.Users.SyncGroupAccess(u.Username, u.Groups)
		for _, c := range changes {
			h.AuditLog.UserAction(user, "idp groups: "+c.String(), ip)
		}
		n += len(changes)
		if err != nil {
			apiErrorResponse(w, "mappings saved, error applying them to "+u.Username, http.StatusInternalServerError, err)
			return
		}
	}
	saved, err := h.Users.GroupMappings()
	if err != nil {
		apiErrorResponse(w, "error getting group mappings", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, GroupMappingsResponse{Mappings: saved, Changes: n})
}
