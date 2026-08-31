package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// channel_webhook.go — HTTP POST notification channel.
//
// Security posture:
//   - SSRF guard: webhook targets are operator-configured, so by
//     default loopback / link-local / private targets are refused
//     unless the deployment explicitly opts in (AllowPrivateTargets).
//   - Optional HMAC-SHA256 signature header (X-Osctrl-Signature) so the
//     receiver can authenticate the payload.
//   - Retries with capped exponential backoff; a slow or dead endpoint
//     must not stall the dispatch worker beyond its timeout budget.

// WebhookConfig is the typed JSON config for webhook channels.
type WebhookConfig struct {
	URL                string `json:"url"`
	Secret             string `json:"secret"`
	TimeoutSeconds     int    `json:"timeoutSeconds"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	// AllowPrivateTargets permits http(s):// targets on loopback or
	// RFC1918 / link-local ranges. Intended for the dev stack's
	// sink-catchall container; production deployments should leave it
	// off so a compromised operator account cannot probe internals.
	AllowPrivateTargets bool `json:"allowPrivateTargets"`
}

// SignatureHeader carries the HMAC of the request body.
const SignatureHeader = "X-Osctrl-Signature"

// webhookMaxRetries caps the delivery attempts per hit.
const webhookMaxRetries = 3

// webhookBackoff is the base backoff between retries.
const webhookBackoff = 500 * time.Millisecond

// webhookPayload is the JSON body POSTed to the receiver.
type webhookPayload struct {
	Rule        string `json:"rule"`
	RuleID      uint   `json:"rule_id"`
	Environment string `json:"environment"`
	Node        string `json:"node"`
	Entity      string `json:"entity"`
	Detail      string `json:"detail"`
	Timestamp   string `json:"timestamp"`
}

type webhookSender struct {
	cfg    WebhookConfig
	client *http.Client
	// now is overridable for tests.
	now func() time.Time
}

func buildWebhook(cfg WebhookConfig) (ChannelSender, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("webhook url: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("webhook url scheme must be http or https")
	}
	if !cfg.AllowPrivateTargets {
		host := u.Hostname()
		if isPrivateHost(host) {
			return nil, fmt.Errorf("webhook target %q is a private/loopback address; set allowPrivateTargets to override (dev only)", host)
		}
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opt-in
	}
	return &webhookSender{
		cfg: cfg,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		now: time.Now,
	}, nil
}

func (s *webhookSender) Name() string { return ChannelWebhook }

// Send delivers the hit as a signed JSON POST with retries.
func (s *webhookSender) Send(h Hit) error {
	body, err := json.Marshal(webhookPayload{
		Rule:        h.RuleName,
		RuleID:      h.RuleID,
		Environment: h.Environment,
		Node:        h.NodeUUID,
		Entity:      h.Entity,
		Detail:      h.Detail,
		Timestamp:   s.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < webhookMaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(webhookBackoff * time.Duration(1<<uint(attempt-1)))
		}
		req, err := http.NewRequest(http.MethodPost, s.cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "osctrl-alerts")
		if s.cfg.Secret != "" {
			req.Header.Set(SignatureHeader, hmacHex(s.cfg.Secret, body))
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		// 4xx (other than 429) means the receiver understood and
		// rejected us — retrying will not help.
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return fmt.Errorf("webhook receiver rejected with status %d", resp.StatusCode)
		}
		lastErr = fmt.Errorf("webhook receiver status %d", resp.StatusCode)
	}
	return fmt.Errorf("webhook delivery failed after %d attempts: %w", webhookMaxRetries, lastErr)
}

// hmacHex computes the HMAC-SHA256 of body keyed by secret, hex-encoded.
func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// isPrivateHost reports whether the hostname resolves to (or is
// literally) a loopback, link-local, or RFC1918 address. Literal IPs are
// checked synchronously; hostnames are resolved once — the SSRF window
// of a DNS-rebinding attacker is narrowed to the build-time check plus
// the transport dial below.
func isPrivateHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateIP(ip)
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Unresolvable host: refuse rather than risk it.
		return true
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}
