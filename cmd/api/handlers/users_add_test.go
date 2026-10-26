package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupUserAdd: environments "dev" (uuid-dev) and "prod" (uuid-prod), global
// admin "root" and non-admin "bob".
func setupUserAdd(t *testing.T) *HandlersApi {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	require.NoError(t, db.Create(&environments.TLSEnvironment{UUID: "uuid-dev", Name: "dev"}).Error)
	require.NoError(t, db.Create(&environments.TLSEnvironment{UUID: "uuid-prod", Name: "prod"}).Error)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "root", Admin: true}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	return CreateHandlersApi(WithDB(db), WithEnvs(envs), WithUsers(userManager), WithAuditLog(auditLog), WithDebugHTTP(&config.YAMLConfigurationDebug{}))
}

func postUserAdd(t *testing.T, h *HandlersApi, caller string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body["username"] = "carol"
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/carol/add", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("username", "carol")
	req.SetPathValue("action", users.ActionAdd)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	h.UserActionHandler(rr, req)
	return rr
}

// permEnvs returns the distinct environments of carol's permission rows.
func permEnvs(t *testing.T, h *HandlersApi) map[string]int {
	t.Helper()
	var perms []users.UserPermission
	require.NoError(t, h.Users.DB.Where("username = ?", "carol").Find(&perms).Error)
	res := map[string]int{}
	for _, p := range perms {
		res[p.Environment]++
	}
	return res
}

func TestUserAddEnvironments(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want map[string]int
	}{
		{"uuid", map[string]any{"environments": []string{"uuid-dev"}}, map[string]int{"uuid-dev": 4}},
		{"name stored as uuid", map[string]any{"environments": []string{"dev"}}, map[string]int{"uuid-dev": 4}},
		{"blank skipped", map[string]any{"environments": []string{"", "  "}}, map[string]int{}},
		{"blank skipped with admin_access", map[string]any{"environments": []string{""}, "admin_access": true}, map[string]int{}},
		{"duplicates deduplicated", map[string]any{"environments": []string{"dev", "uuid-dev", " dev "}}, map[string]int{"uuid-dev": 4}},
		{"admin grants all envs", map[string]any{"admin": true, "environments": []string{""}}, map[string]int{"uuid-dev": 4, "uuid-prod": 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := setupUserAdd(t)
			rr := postUserAdd(t, h, "root", c.body)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.Equal(t, c.want, permEnvs(t, h))
		})
	}
}

func TestUserAddBlankEnvAdminAccessIsNotShadowAdmin(t *testing.T) {
	h := setupUserAdd(t)
	rr := postUserAdd(t, h, "root", map[string]any{"environments": []string{""}, "admin_access": true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.False(t, h.Users.CheckPermissionsContext(users.WithPermissionCache(context.Background()), "carol", users.AdminLevel, users.NoEnvironment))
	require.False(t, h.Users.CheckPermissions("carol", users.AdminLevel, users.NoEnvironment))
}

func TestUserAddAdminAccessOnOneEnv(t *testing.T) {
	h := setupUserAdd(t)
	rr := postUserAdd(t, h, "root", map[string]any{"environments": []string{"prod"}, "admin_access": true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, map[string]int{"uuid-prod": 4}, permEnvs(t, h))
	require.True(t, h.Users.CheckPermissions("carol", users.AdminLevel, "uuid-prod"))
	require.False(t, h.Users.CheckPermissions("carol", users.AdminLevel, "uuid-dev"))
	require.False(t, h.Users.CheckPermissions("carol", users.AdminLevel, users.NoEnvironment))
}

func TestUserAddUnknownEnvironmentIs404AndCreatesNothing(t *testing.T) {
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprint(admin), func(t *testing.T) {
			h := setupUserAdd(t)
			rr := postUserAdd(t, h, "root", map[string]any{"admin": admin, "environments": []string{"dev", "nope"}})
			require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
			require.Contains(t, rr.Body.String(), "environment not found: nope")
			require.False(t, h.Users.Exists("carol"))
			require.Empty(t, permEnvs(t, h))
		})
	}
}

func TestUserAddUnchangedBehaviour(t *testing.T) {
	h := setupUserAdd(t)
	rr := postUserAdd(t, h, "bob", map[string]any{"environments": []string{"dev"}})
	require.Equal(t, http.StatusForbidden, rr.Code)
	require.False(t, h.Users.Exists("carol"))

	require.Equal(t, http.StatusOK, postUserAdd(t, h, "root", map[string]any{"environments": []string{"dev"}}).Code)
	rr = postUserAdd(t, h, "root", map[string]any{"environments": []string{"dev"}})
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Contains(t, rr.Body.String(), "error adding user")
}
