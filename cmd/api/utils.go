package main

import (
	"strings"

	"github.com/jmpsec/osctrl/pkg/config"
)

// Helper to compose paths for API
func _apiPath(target string) string {
	return apiPrefixPath + apiVersionPath + target
}

// Helper to convert YAML settings loaded from file to settings. Optional
// sections are only set when present in the YAML (non-nil); missing sections
// stay nil in ServiceParameters so Seed/Resolve can fill them from the DB.
func loadedYAMLToServiceParams(yml config.APIConfiguration, loadedFile string) *config.ServiceParameters {
	params := &config.ServiceParameters{
		ConfigFlag:        true,
		ServiceConfigFile: loadedFile,
		Service:           &yml.Service,
		DB:                &yml.DB,
		Redis:             &yml.Redis,
		RateLimits:        config.DefaultRateLimitsPtr(),
	}
	// Optional sections — only set when the YAML provided them.
	if yml.Osquery != nil {
		params.Osquery = yml.Osquery
	}
	if yml.SAML != nil {
		params.SAML = yml.SAML
	}
	if yml.OIDC != nil {
		params.OIDC = yml.OIDC
	}
	if yml.JWT != nil {
		params.JWT = yml.JWT
	}
	if yml.TLS != nil {
		params.TLS = yml.TLS
	}
	if yml.Logger != nil {
		params.Logger = yml.Logger
	}
	if yml.Carver != nil {
		params.Carver = yml.Carver
	}
	if yml.Debug != nil {
		params.Debug = yml.Debug
	}
	if yml.RateLimits != nil {
		params.RateLimits = yml.RateLimits
	}
	return params
}

// splitAndTrim turns a comma-separated flag value into a slice, dropping
// empty entries and surrounding whitespace.
func splitAndTrim(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// mfaIssuerName is the label authenticator apps and the WebAuthn prompt show
// for this deployment. Falls back to the service host, then to a constant, so
// users never see an empty or confusing prompt.
func mfaIssuerName(params *config.ServiceParameters) string {
	if params.Service.MFAIssuer != "" {
		return params.Service.MFAIssuer
	}
	if params.Service.Host != "" {
		return "osctrl (" + params.Service.Host + ")"
	}
	return "osctrl"
}
