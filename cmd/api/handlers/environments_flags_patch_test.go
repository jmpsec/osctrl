package handlers

import (
	"context"
	"encoding/json"
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

// Environment flags are a plain-text osquery flagfile, not JSON. osctrld
// nodes are served exactly what is stored here, so an empty value must stay
// empty (the generated defaults are served instead), never become "{}".

func setupEnvConfigPatch(t *testing.T) (*HandlersApi, *environments.EnvManager) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	require.NoError(t, db.Create(&environments.TLSEnvironment{UUID: "env-a", Name: "a", Flags: "--old=1"}).Error)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "root", Admin: true}))
	return CreateHandlersApi(WithDB(db), WithEnvs(envs), WithUsers(userManager), WithAuditLog(auditLog), WithDebugHTTP(&config.YAMLConfigurationDebug{})), envs
}

func patchEnvConfig(t *testing.T, h *HandlersApi, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPatch, "/x", strings.NewReader(string(raw)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("env", "a")
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "root"}))
	rr := httptest.NewRecorder()
	h.EnvironmentConfigPatchHandler(rr, req)
	return rr
}

func TestEnvConfigPatchStoresPlainTextFlags(t *testing.T) {
	h, envs := setupEnvConfigPatch(t)
	flags := "--host_identifier=uuid\n--tls_hostname=osctrl.example\n--enroll_secret_path=__SECRET_FILE__"
	rr := patchEnvConfig(t, h, map[string]string{"flags": "\n" + flags + "\n"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	env, err := envs.Get("a")
	require.NoError(t, err)
	require.Equal(t, flags, env.Flags)
}

func TestEnvConfigPatchKeepsEmptyFlagsEmpty(t *testing.T) {
	h, envs := setupEnvConfigPatch(t)
	rr := patchEnvConfig(t, h, map[string]string{"flags": "  \n"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	env, err := envs.Get("a")
	require.NoError(t, err)
	require.Empty(t, env.Flags, "an empty flagfile falls back to generated flags; {} would be served as-is")
}

func TestEnvConfigPatchRejectsLinesThatAreNotFlags(t *testing.T) {
	h, envs := setupEnvConfigPatch(t)
	rr := patchEnvConfig(t, h, map[string]string{"flags": "--good=1\n{\"oops\": true}"})
	require.Equal(t, http.StatusBadRequest, rr.Code)
	env, err := envs.Get("a")
	require.NoError(t, err)
	require.Equal(t, "--old=1", env.Flags, "a rejected patch writes nothing")
}

func TestEnvConfigPatchAllowsFlagfileComments(t *testing.T) {
	h, _ := setupEnvConfigPatch(t)
	rr := patchEnvConfig(t, h, map[string]string{"flags": "# investigation\n--verbose=true\n\n-disable_events=false"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestEnvConfigPatchStillValidatesJSONSections(t *testing.T) {
	h, _ := setupEnvConfigPatch(t)
	rr := patchEnvConfig(t, h, map[string]string{"options": "--not-json"})
	require.Equal(t, http.StatusBadRequest, rr.Code)
}
