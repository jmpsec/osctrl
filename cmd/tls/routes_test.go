package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/cmd/tls/handlers"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/stretchr/testify/require"
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
