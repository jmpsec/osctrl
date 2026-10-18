package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/cmd/tls/handlers"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestRegisterRoutesAllEnabled registers every route at once: Go's ServeMux
// panics at startup when two patterns overlap with neither more specific.
func TestRegisterRoutesAllEnabled(t *testing.T) {
	params := &config.ServiceParameters{
		Osquery:         &config.YAMLConfigurationOsquery{Config: true, Logger: true, Query: true, Carve: true},
		ConfigEndpoints: &config.YAMLConfigurationEndpoints{{}},
		Osctrld:         &config.YAMLConfigurationOsctrld{Enabled: true},
	}
	h := &handlers.HandlersTLS{Extensions: &extensions.Manager{}}
	mux := http.NewServeMux()
	require.NotPanics(t, func() { registerRoutes(mux, h, params, http.NotFoundHandler()) })

	const env = "/11111111-1111-4111-8111-111111111111/"
	for path, want := range map[string]string{
		env + environments.DefaultExtensionsPath:                 "POST /{env}/" + environments.DefaultExtensionsPath,
		env + environments.DefaultExtensionPath:                  "POST /{env}/" + environments.DefaultExtensionPath,
		env + "secret/" + environments.DefaultConfigEndpointPath: "POST /{env}/{secret}/" + environments.DefaultConfigEndpointPath,
		env + environments.DefaultFlagsPath:                      "POST /{env}/" + environments.DefaultFlagsPath,
	} {
		_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, path, nil))
		require.Equal(t, want, pattern, path)
	}
}

func TestRegisterRoutesWithoutExtensions(t *testing.T) {
	params := &config.ServiceParameters{
		Osquery: &config.YAMLConfigurationOsquery{},
		Osctrld: &config.YAMLConfigurationOsctrld{Enabled: true},
	}
	mux := http.NewServeMux()
	registerRoutes(mux, &handlers.HandlersTLS{}, params, http.NotFoundHandler())
	_, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, "/11111111-1111-4111-8111-111111111111/"+environments.DefaultExtensionsPath, nil))
	require.NotEqual(t, "POST /{env}/"+environments.DefaultExtensionsPath, pattern)
}

// Every osctrld route goes through the osctrld limits; enroll does not.
func TestRegisterRoutesRateLimitsOsctrld(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:routes_osctrld?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	envs := environments.CreateEnvironment(db)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Secret: "osctrld-secret"}
	require.NoError(t, db.Create(&env).Error)
	limits := config.DefaultRateLimits()
	limits.OsctrldAuth.Burst = 1
	h := handlers.CreateHandlersTLS(
		handlers.WithEnvs(envs),
		handlers.WithExtensions(&extensions.Manager{}),
		handlers.WithOsqueryValues(&config.YAMLConfigurationOsquery{}),
		handlers.WithOsctrldLimits(handlers.NewOsctrldLimits(limits)),
	)
	params := &config.ServiceParameters{
		Osquery: &config.YAMLConfigurationOsquery{},
		Osctrld: &config.YAMLConfigurationOsctrld{Enabled: true},
	}
	enrolls := 0
	mux := http.NewServeMux()
	registerRoutes(mux, h, params, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { enrolls++ }))
	post := func(path, secret string) int {
		r := httptest.NewRequest(http.MethodPost, "/"+env.UUID+"/"+path, strings.NewReader(`{"secret":"`+secret+`"}`))
		r.RemoteAddr = "198.51.100.7:40000"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusForbidden, post(environments.DefaultCertPath, "wrong"))
	for _, path := range []string{
		environments.DefaultFlagsPath,
		environments.DefaultCertPath,
		environments.DefaultVerifyPath,
		"enroll/linux/" + environments.DefaultScriptPath,
		environments.DefaultExtensionsPath,
		environments.DefaultExtensionPath,
	} {
		require.Equal(t, http.StatusTooManyRequests, post(path, env.Secret), path)
	}
	for i := 0; i < 5; i++ {
		post(environments.DefaultEnrollPath, "wrong")
	}
	require.Equal(t, 5, enrolls, "enroll keeps its own limiter")
}
