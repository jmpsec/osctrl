package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/stretchr/testify/require"
)

func TestMissingAPIConfiguration(t *testing.T) {
	require.False(t, missingAPIConfiguration(apiclient.JSONConfigurationAPI{URL: "https://osctrl", Token: "t"}))
	require.True(t, missingAPIConfiguration(apiclient.JSONConfigurationAPI{Token: "t"}))
	require.True(t, missingAPIConfiguration(apiclient.JSONConfigurationAPI{URL: "https://osctrl"}))
	require.True(t, missingAPIConfiguration(apiclient.JSONConfigurationAPI{}))
}

// Non-interactive contexts (pipes, scripts, CI) must fail with guidance
// instead of blocking on a prompt — while keeping partial values so the
// error names exactly what is missing.
func TestPromptMissingAPIConfigurationNonInteractive(t *testing.T) {
	both := apiclient.JSONConfigurationAPI{}
	err := promptMissingAPIConfiguration(&both)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no API configuration found")

	urlOnly := apiclient.JSONConfigurationAPI{URL: "https://osctrl"}
	err = promptMissingAPIConfiguration(&urlOnly)
	require.Error(t, err)
	require.Contains(t, err.Error(), "token is required")

	tokenOnly := apiclient.JSONConfigurationAPI{Token: "t"}
	err = promptMissingAPIConfiguration(&tokenOnly)
	require.Error(t, err)
	require.Contains(t, err.Error(), "URL is required")

	complete := apiclient.JSONConfigurationAPI{URL: "https://osctrl", Token: "t"}
	require.NoError(t, promptMissingAPIConfiguration(&complete))
	require.Equal(t, "https://osctrl", complete.URL)
	require.Equal(t, "t", complete.Token)
}
