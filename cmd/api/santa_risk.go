package main

import (
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/rs/zerolog/log"
)

// santaRiskEngine builds the service-wide Santa risk checks from the service
// config. It always returns an engine, so environments can run their own
// checks even when no service-wide one is configured. The service-wide
// webhook URL comes from the deployment's own config, never from the API, so
// private targets are allowed; environment webhooks use a public-only client.
func santaRiskEngine(s *config.YAMLConfigurationService) *santa.RiskEngine {
	timeout := time.Duration(s.SantaRiskTimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	ttl := time.Duration(s.SantaRiskTTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	var checks []santa.RiskCheck
	if s.SantaVirusTotalKey != "" {
		checks = append(checks, santa.VirusTotal{Key: s.SantaVirusTotalKey, Threshold: s.SantaVirusTotalThreshold, Client: client})
	}
	if s.SantaRiskWebhookURL != "" {
		checks = append(checks, santa.RiskWebhook{URL: s.SantaRiskWebhookURL, Secret: s.SantaRiskWebhookSecret, Client: client})
	}
	names := make([]string, 0, len(checks))
	for _, c := range checks {
		names = append(names, c.Name())
	}
	log.Info().Strs("checks", names).Msg("Santa service-wide risk checks")
	return &santa.RiskEngine{Checks: checks, TTL: ttl, Timeout: timeout, Client: client, PublicClient: santa.NewPublicClient(timeout)}
}
