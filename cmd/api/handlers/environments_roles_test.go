package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func setupEnvRoles(t *testing.T) *HandlersApi {
	t.Helper()
	h := setupUserAdd(t)
	h.Tags = tags.CreateTagManager(h.DB)
	require.NoError(t, h.DB.AutoMigrate(&settings.SettingValue{}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "em", EnvManager: true}))
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	return h
}

func envReq(h *HandlersApi, caller, method, body, env string, fn http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/environments", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	if env != "" {
		req.SetPathValue("env", env)
	}
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: caller}))
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

func TestEnvManagerCreatesEnvAndBecomesEnvAdmin(t *testing.T) {
	h := setupEnvRoles(t)
	rr := envReq(h, "em", http.MethodPost, `{"name":"newenv","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	env, err := h.Envs.Get("newenv")
	require.NoError(t, err)
	require.True(t, h.Users.CheckPermissions("em", users.AdminLevel, env.UUID))
	require.True(t, h.Users.CheckPermissions("em", users.UserLevel, env.UUID))
}

func TestEnvManagerNotAdminElsewhere(t *testing.T) {
	h := setupEnvRoles(t)
	rr := envReq(h, "em", http.MethodPost, `{"name":"newenv","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.False(t, h.Users.CheckPermissions("em", users.AdminLevel, "uuid-dev"))
}

func TestEnvManagerRenamesAndDeletesOwnEnv(t *testing.T) {
	h := setupEnvRoles(t)
	require.NoError(t, h.Users.SetEnvAdmin("em", "uuid-dev", true))
	require.NoError(t, h.Users.SetEnvAdmin("em", "uuid-prod", true))
	rr := envReq(h, "em", http.MethodPatch, `{"name":"renamed"}`, "uuid-dev", h.EnvironmentUpdateHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = envReq(h, "em", http.MethodDelete, "", "uuid-prod", h.EnvironmentDeleteHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = envReq(h, "em", http.MethodPost, `{"action":"edit","uuid":"uuid-dev","hostname":"new.example.com"}`, "", h.EnvActionsHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// An env manager must hold env-admin on an env to change it, or renaming a
// foreign env and recreating its name would hand them its nodes.
func TestEnvManagerNeedsEnvAdminToChangeEnv(t *testing.T) {
	h := setupEnvRoles(t)
	// EnvActionsHandler delete wants a canonical UUID.
	const target = "11111111-2222-3333-4444-555555555555"
	require.NoError(t, h.DB.Create(&environments.TLSEnvironment{UUID: target, Name: "secure"}).Error)
	cases := []struct {
		name, method, body, env string
		fn                      http.HandlerFunc
	}{
		{"rename", http.MethodPatch, `{"name":"renamed"}`, target, h.EnvironmentUpdateHandler},
		{"patch", http.MethodPatch, `{"accept_enrolls":true}`, "secure", h.EnvironmentUpdateHandler},
		{"delete", http.MethodDelete, "", target, h.EnvironmentDeleteHandler},
		{"action delete", http.MethodPost, `{"action":"delete","name":"secure","uuid":"` + target + `"}`, "", h.EnvActionsHandler},
		{"action edit", http.MethodPost, `{"action":"edit","uuid":"` + target + `","hostname":"evil.example.com"}`, "", h.EnvActionsHandler},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Env admin of dev only: prod stays out of reach.
			require.NoError(t, h.Users.SetEnvAdmin("em", "uuid-dev", true))
			rr := envReq(h, "em", c.method, c.body, c.env, c.fn)
			require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			env, err := h.Envs.GetByUUID(target)
			require.NoError(t, err)
			require.Equal(t, "secure", env.Name)
			require.Empty(t, env.Hostname)
			require.False(t, env.AcceptEnrolls)
		})
	}
	// A superuser needs no env-admin row.
	rr := envReq(h, "root", http.MethodPatch, `{"hostname":"ok.example.com"}`, target, h.EnvironmentUpdateHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestEnvNameCollisionsRefused(t *testing.T) {
	h := setupEnvRoles(t)
	require.NoError(t, h.Users.SetEnvAdmin("em", "uuid-dev", true))
	for _, caller := range []string{"em", "root"} {
		rr := envReq(h, caller, http.MethodPost, `{"name":"prod","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
		require.Equal(t, http.StatusConflict, rr.Code, caller)
		rr = envReq(h, caller, http.MethodPost, `{"action":"create","name":"prod","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvActionsHandler)
		require.Equal(t, http.StatusBadRequest, rr.Code, caller)
		rr = envReq(h, caller, http.MethodPatch, `{"name":"prod"}`, "uuid-dev", h.EnvironmentUpdateHandler)
		require.Equal(t, http.StatusConflict, rr.Code, caller)
	}
	env, err := h.Envs.GetByUUID("uuid-dev")
	require.NoError(t, err)
	require.Equal(t, "dev", env.Name)
}

// The takeover chain: rename prod away, then create a new prod as its env admin.
func TestEnvManagerCannotTakeOverEnvByRename(t *testing.T) {
	h := setupEnvRoles(t)
	rr := envReq(h, "em", http.MethodPatch, `{"name":"prod-old"}`, "prod", h.EnvironmentUpdateHandler)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	rr = envReq(h, "em", http.MethodPost, `{"name":"prod","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.False(t, h.Users.CheckPermissions("em", users.AdminLevel, "uuid-prod"))
	env, err := h.Envs.Get("prod")
	require.NoError(t, err)
	require.Equal(t, "uuid-prod", env.UUID)
}

func TestReadOnlyCannotCreateEnv(t *testing.T) {
	h := setupEnvRoles(t)
	rr := envReq(h, "ro", http.MethodPost, `{"name":"newenv","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusForbidden, rr.Code)
}

func TestEnvActionsCreateGrantsNonSuperuserCreator(t *testing.T) {
	h := setupEnvRoles(t)
	rr := envReq(h, "em", http.MethodPost, `{"action":"create","name":"viaact","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvActionsHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	env, err := h.Envs.Get("viaact")
	require.NoError(t, err)
	require.True(t, h.Users.CheckPermissions("em", users.AdminLevel, env.UUID))
}

// A superuser rename moves the env's nodes, and a superuser delete is refused
// while nodes remain, so no name is ever left behind for someone to recreate
// and inherit the fleet.
func TestEnvNodesNeverOrphanedByRenameOrDelete(t *testing.T) {
	h := setupEnvRoles(t)
	require.NoError(t, h.DB.AutoMigrate(&nodes.OsqueryNode{}))
	require.NoError(t, h.DB.Create(&nodes.OsqueryNode{UUID: "n1", Environment: "prod"}).Error)

	rr := envReq(h, "root", http.MethodDelete, "", "prod", h.EnvironmentDeleteHandler)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.True(t, h.Envs.Exists("prod"))
	const fleetUUID = "11111111-1111-4111-8111-111111111111"
	require.NoError(t, h.Envs.Create(&environments.TLSEnvironment{Name: "fleet", UUID: fleetUUID}))
	require.NoError(t, h.DB.Create(&nodes.OsqueryNode{UUID: "n3", Environment: "fleet"}).Error)
	rr = envReq(h, "root", http.MethodPost, `{"action":"delete","uuid":"`+fleetUUID+`","name":"fleet"}`, "", h.EnvActionsHandler)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.True(t, h.Envs.Exists("fleet"))

	rr = envReq(h, "root", http.MethodPatch, `{"name":"prod-old"}`, "prod", h.EnvironmentUpdateHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var node nodes.OsqueryNode
	require.NoError(t, h.DB.Where("uuid = ?", "n1").First(&node).Error)
	require.Equal(t, "prod-old", node.Environment)

	// The freed name now carries no nodes: an env manager recreating it gets an empty env.
	rr = envReq(h, "em", http.MethodPost, `{"name":"prod","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var n int64
	require.NoError(t, h.DB.Model(&nodes.OsqueryNode{}).Where("environment = ?", "prod").Count(&n).Error)
	require.Zero(t, n)

	// Nodes orphaned before this fix (a name with nodes but no env) can't be adopted.
	require.NoError(t, h.DB.Create(&nodes.OsqueryNode{UUID: "n2", Environment: "ghost"}).Error)
	rr = envReq(h, "em", http.MethodPost, `{"name":"ghost","hostname":"h.example.com","type":"osquery","icon":"cloud"}`, "", h.EnvironmentCreateHandler)
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
}
