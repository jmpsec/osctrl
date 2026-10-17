package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// osctrld writes whatever these endpoints return to the node's flagfile and
// restarts osqueryd when it changes, so they must serve the flags operators
// edit on the environment, not a freshly generated default set.
func newOsctrldFlagsHandlers(t *testing.T, flags string) (*HandlersTLS, environments.TLSEnvironment) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Secret: "osctrld-test-secret", Hostname: "osctrl.example", Flags: flags}
	require.NoError(t, db.Create(&env).Error)
	return CreateHandlersTLS(WithEnvs(envs), WithOsqueryValues(&config.YAMLConfigurationOsquery{Config: true, Logger: true})), env
}

func osctrldPost(t *testing.T, h http.HandlerFunc, env environments.TLSEnvironment, req types.FlagsRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/osctrld", bytes.NewReader(body))
	r.SetPathValue("env", env.UUID)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

const editedFlags = "--host_identifier=uuid\n--enroll_secret_path=__SECRET_FILE__\n--tls_server_certs=__CERT_FILE__\n--extensions_autoload=/etc/osquery/extensions.load\n"

func TestOsctrldFlagsServeTheEnvironmentFlags(t *testing.T) {
	h, env := newOsctrldFlagsHandlers(t, editedFlags)
	req := types.FlagsRequest{Secret: env.Secret, SecrefFile: "/etc/osquery/osctrl-env.secret", CertFile: "/etc/osquery/osctrl-env.crt"}
	want := "--host_identifier=uuid\n--enroll_secret_path=/etc/osquery/osctrl-env.secret\n--tls_server_certs=/etc/osquery/osctrl-env.crt\n--extensions_autoload=/etc/osquery/extensions.load\n"

	w := osctrldPost(t, h.FlagsHandler, env, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, want, w.Body.String())

	w = osctrldPost(t, h.VerifyHandler, env, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp types.VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, want, resp.Flags, "verify must compare against the same flags the flags endpoint serves")
}

func TestOsctrldFlagsKeepPlaceholdersWithoutPaths(t *testing.T) {
	// Same contract as the generated flags: no path given, placeholder kept.
	h, env := newOsctrldFlagsHandlers(t, editedFlags)
	w := osctrldPost(t, h.FlagsHandler, env, types.FlagsRequest{Secret: env.Secret})
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, editedFlags, w.Body.String())
}

func TestOsctrldFlagsFallBackToGeneratedWhenUnset(t *testing.T) {
	// Environments created before flags were stored have none; they keep
	// getting the generated defaults rather than an empty flagfile.
	h, env := newOsctrldFlagsHandlers(t, "  \n")
	w := osctrldPost(t, h.FlagsHandler, env, types.FlagsRequest{Secret: env.Secret})
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "--tls_hostname=osctrl.example")
	require.Contains(t, w.Body.String(), "--config_plugin=tls")
}

func TestOsctrldFlagsFallBackOverAStoredEmptyObject(t *testing.T) {
	// Clearing flags through the API used to store "{}"; nodes must get the
	// generated defaults rather than a flagfile with "{}" in it.
	h, env := newOsctrldFlagsHandlers(t, "{}")
	w := osctrldPost(t, h.FlagsHandler, env, types.FlagsRequest{Secret: env.Secret})
	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "{}")
	require.Contains(t, w.Body.String(), "--tls_hostname=osctrl.example")
}

func TestOsctrldFlagsRejectWrongSecret(t *testing.T) {
	h, env := newOsctrldFlagsHandlers(t, editedFlags)
	require.Equal(t, http.StatusForbidden, osctrldPost(t, h.FlagsHandler, env, types.FlagsRequest{Secret: "wrong"}).Code)
	require.Equal(t, http.StatusForbidden, osctrldPost(t, h.VerifyHandler, env, types.FlagsRequest{Secret: "wrong"}).Code)
}
