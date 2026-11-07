package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func TestMeHandlerReturnsRoles(t *testing.T) {
	h := setupUserAdd(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "carol", AlertAdmin: true, ReadOnlyAdmin: true}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "carol"}))
	rr := httptest.NewRecorder()
	h.MeHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := rr.Body.String()
	for _, want := range []string{`"alert_admin":true`, `"read_only_admin":true`, `"user_admin":false`, `"env_manager":false`, `"admin":false`} {
		require.Contains(t, body, want)
	}
}

func TestUserViewIncludesRoles(t *testing.T) {
	v := projectAdminUserView(users.AdminUser{UserAdmin: true, EnvManager: false, ReadOnlyAdmin: true, AlertAdmin: false})
	require.True(t, v.UserAdmin)
	require.False(t, v.EnvManager)
	require.True(t, v.ReadOnlyAdmin)
	require.False(t, v.AlertAdmin)
}

func TestMePatchHandlerReturnsRolesAndPermissions(t *testing.T) {
	h := setupUserAdd(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "dave", EnvManager: true, AlertAdmin: true}))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/me", strings.NewReader(`{"fullname":"Dave"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "dave"}))
	rr := httptest.NewRecorder()
	h.MePatchHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	body := rr.Body.String()
	for _, want := range []string{`"env_manager":true`, `"alert_admin":true`, `"user_admin":false`, `"read_only_admin":false`, `"permissions":{`} {
		require.Contains(t, body, want)
	}
}

func setupRoles(t *testing.T) *HandlersApi {
	t.Helper()
	h := setupUserAdd(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ua", UserAdmin: true}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "alerty", AlertAdmin: true}))
	return h
}

func getUsersAs(h *HandlersApi, caller string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	h.UsersHandler(rr, req)
	return rr.Code
}

func refreshTokenAs(h *HandlersApi, caller, target string) int {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+target+"/token/refresh", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("username", target)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	h.RefreshUserTokenHandler(rr, req)
	return rr.Code
}

func TestUserAdminCannotGrantSuperuser(t *testing.T) {
	h := setupRoles(t)
	rr := postUserAction(t, h, "ua", "bob", users.ActionEdit, map[string]any{"admin": true})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.False(t, h.Users.IsAdmin("bob"))
	rr = postUserAdd(t, h, "ua", map[string]any{"admin": true, "password": "pw"})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.False(t, h.Users.Exists("carol"))
}

func TestUserAdminCannotEditSuperuser(t *testing.T) {
	h := setupRoles(t)
	rr := postUserAction(t, h, "ua", "root", users.ActionEdit, map[string]any{"email": "x@example.com"})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	rr = postUserAction(t, h, "ua", "root", users.ActionRemove, map[string]any{})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.Equal(t, http.StatusForbidden, refreshTokenAs(h, "ua", "root"))
	u, err := h.Users.Get("root")
	require.NoError(t, err)
	require.True(t, u.Admin)
	require.Empty(t, u.Email)
	require.Empty(t, u.APIToken)
}

func TestUserAdminCanGrantRoles(t *testing.T) {
	h := setupRoles(t)
	rr := postUserAction(t, h, "ua", "bob", users.ActionEdit, map[string]any{"alert_admin": true, "user_admin": true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	u, err := h.Users.Get("bob")
	require.NoError(t, err)
	require.True(t, u.AlertAdmin)
	require.True(t, u.UserAdmin)
	require.False(t, u.Admin)
}

func TestUserAdminCanDropOwnRole(t *testing.T) {
	h := setupRoles(t)
	rr := postUserAction(t, h, "ua", "ua", users.ActionEdit, map[string]any{"user_admin": false})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	u, err := h.Users.Get("ua")
	require.NoError(t, err)
	require.False(t, u.UserAdmin)
}

func TestReadOnlyCanListNotEdit(t *testing.T) {
	h := setupRoles(t)
	require.Equal(t, http.StatusOK, getUsersAs(h, "ro"))
	rr := postUserAction(t, h, "ro", "bob", users.ActionEdit, map[string]any{"email": "x@example.com"})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	u, err := h.Users.Get("bob")
	require.NoError(t, err)
	require.Empty(t, u.Email)
}

func TestRolesOmittedLeavesRoles(t *testing.T) {
	h := setupRoles(t)
	rr := postUserAction(t, h, "root", "alerty", users.ActionEdit, map[string]any{"email": "a@example.com"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	u, err := h.Users.Get("alerty")
	require.NoError(t, err)
	require.True(t, u.AlertAdmin)
	require.Equal(t, "a@example.com", u.Email)
}

func TestPlainUserForbidden(t *testing.T) {
	h := setupRoles(t)
	for _, caller := range []string{"bob", "alerty"} {
		require.Equal(t, http.StatusForbidden, getUsersAs(h, caller), caller)
		rr := postUserAction(t, h, caller, "ro", users.ActionEdit, map[string]any{"email": "x@example.com"})
		require.Equal(t, http.StatusForbidden, rr.Code, caller)
	}
}

// A user admin must not touch a superuser's permissions or API token.
func TestUserAdminCannotChangeSuperuserPermissionsOrToken(t *testing.T) {
	h := setupRoles(t)
	require.NoError(t, h.Users.SetEnvUser("root", "uuid-dev", true))
	require.NoError(t, h.Users.UpdateToken("root", "root-token", time.Now().Add(time.Hour)))
	rootPerms := func() []users.UserPermission {
		var perms []users.UserPermission
		require.NoError(t, h.Users.DB.Where("username = ?", "root").Order("id").Find(&perms).Error)
		return perms
	}
	before := rootPerms()
	require.NotEmpty(t, before)
	vars := map[string]string{"username": "root"}
	access := `"access":{"user":false,"query":false,"carve":false,"admin":false}`
	cases := []struct {
		name, method, body string
		fn                 http.HandlerFunc
	}{
		{"set permissions", http.MethodPost, `{"env_uuid":"uuid-dev",` + access + `}`, h.SetUserPermissionsHandler},
		{"set permissions all", http.MethodPost, `{` + access + `}`, h.SetUserPermissionsAllHandler},
		{"delete token", http.MethodDelete, "", h.DeleteUserTokenHandler},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := roReq(h, "ua", c.method, "/api/v1/users/root", c.body, vars, c.fn)
			require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			require.Equal(t, before, rootPerms())
			u, err := h.Users.Get("root")
			require.NoError(t, err)
			require.Equal(t, "root-token", u.APIToken)
		})
	}
}

func TestSetPermissionsTiersAndScopeTags(t *testing.T) {
	h := setupRoles(t)
	h.Tags = tags.CreateTagManager(h.DB)
	devEnv, err := h.Envs.GetByUUID("uuid-dev")
	require.NoError(t, err)
	prodEnv, err := h.Envs.GetByUUID("uuid-prod")
	require.NoError(t, err)
	require.NoError(t, h.Tags.NewTag("web", "", "", "", "root", devEnv.ID, false, tags.TagTypeCustom, ""))
	require.NoError(t, h.Tags.NewTag("db", "", "", "", "root", prodEnv.ID, false, tags.TagTypeCustom, ""))
	devTag, err := h.Tags.Get("web", devEnv.ID)
	require.NoError(t, err)
	prodTag, err := h.Tags.Get("db", prodEnv.ID)
	require.NoError(t, err)

	post := func(body string) *httptest.ResponseRecorder {
		return roReq(h, "root", http.MethodPost, "/api/v1/users/bob/permissions", body, map[string]string{"username": "bob"}, h.SetUserPermissionsHandler)
	}
	rr := post(fmt.Sprintf(`{"env_uuid":"uuid-dev","access":{"user":true,"query":true,"query_tier":"tags","scope_tags":[%d]}}`, devTag.ID))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	acc, err := h.Users.GetEnvAccess("bob", "uuid-dev")
	require.NoError(t, err)
	require.Equal(t, "tags", acc.QueryTier)
	require.Equal(t, []uint{devTag.ID}, acc.ScopeTags)

	rr = post(fmt.Sprintf(`{"env_uuid":"uuid-dev","access":{"user":true,"query_tier":"tags","scope_tags":[%d]}}`, prodTag.ID))
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "scope tag not in environment")

	rr = post(`{"env_uuid":"uuid-dev","access":{"user":true,"query_tier":"bogus"}}`)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())

	rr = roReq(h, "root", http.MethodPost, "/api/v1/users/bob/permissions/all", fmt.Sprintf(`{"access":{"user":true,"scope_tags":[%d]}}`, devTag.ID), map[string]string{"username": "bob"}, h.SetUserPermissionsAllHandler)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "scope_tags needs a single environment")

	// deleting the tag drops the grant
	rr = roReq(h, "root", http.MethodPost, "/api/v1/tags/uuid-dev/remove", `{"name":"web"}`, map[string]string{"env": "uuid-dev", "action": tags.ActionRemove}, h.TagsActionHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	ids, err := h.Users.ScopeTagIDsContext(context.Background(), "bob", "uuid-dev")
	require.NoError(t, err)
	require.Empty(t, ids)
}
