package main

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestSantaRiskEngine(t *testing.T) {
	require.Nil(t, santaRiskEngine(&config.YAMLConfigurationService{}), "off without a check")

	e := santaRiskEngine(&config.YAMLConfigurationService{SantaVirusTotalKey: "k", SantaVirusTotalThreshold: 2})
	require.Len(t, e.Checks, 1)
	require.Equal(t, "virustotal", e.Checks[0].Name())
	require.Equal(t, 24*time.Hour, e.TTL)
	require.Equal(t, 10*time.Second, e.Timeout)

	e = santaRiskEngine(&config.YAMLConfigurationService{
		SantaVirusTotalKey: "k", SantaRiskWebhookURL: "https://risk.example.com", SantaRiskTTLHours: 6, SantaRiskTimeoutSeconds: 3600,
	})
	require.Len(t, e.Checks, 2)
	require.Equal(t, 6*time.Hour, e.TTL)
	require.Equal(t, 10*time.Second, e.Timeout, "an out-of-range timeout falls back to the default")
}
