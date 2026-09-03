package alerts

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// channels.go — pluggable notification channels (logsinks Registry
// pattern). Each channel row in alert_channels has a Type ("webhook",
// "email", …) and a JSON Config validated against this Registry. The
// FieldSpec schema lets the SPA render a typed form generically without
// shipping a per-type component, exactly like log sinks.

// Channel types.
const (
	ChannelWebhook = "webhook"
	ChannelEmail   = "email"
)

// ChannelSpec describes one supported channel type.
type ChannelSpec struct {
	Type         string
	Description  string
	HasSecret    bool
	SecretFields []string
	Fields       []FieldSpec
	// Decode unmarshals a raw JSON Config into the typed struct the
	// sender expects.
	Decode func(json.RawMessage) (any, error)
	// Build instantiates a ChannelSender from a decoded config.
	Build func(any) (ChannelSender, error)
}

// ChannelSender delivers one notification for one hit. Implementations
// must be safe for concurrent use from the worker pool.
type ChannelSender interface {
	Send(h Hit) error
	// Name identifies the channel in logs and history.
	Name() string
}

// ChannelRegistry maps each channel type to its spec. Adding a channel
// type means: implement the sender, add the config struct here, add a
// ChannelSpec entry.
var ChannelRegistry = map[string]ChannelSpec{
	ChannelWebhook: {
		Type:         ChannelWebhook,
		Description:  "HTTP POST to a URL with the alert as JSON",
		HasSecret:    true,
		SecretFields: []string{"secret"},
		Fields: []FieldSpec{
			{Name: "url", Label: "URL", Type: FieldString, Required: true, Placeholder: "https://example.com/hook", Help: "HTTPS URL receiving the alert as a JSON POST."},
			{Name: "secret", Label: "HMAC secret", Type: FieldSecret, Help: "When set, the payload is signed with X-Osctrl-Signature (HMAC-SHA256, hex)."},
			{Name: "timeoutSeconds", Label: "Timeout (seconds)", Type: FieldInteger, Default: 10, Help: "Per-request timeout, including retries."},
			{Name: "insecureSkipVerify", Label: "Skip TLS verify", Type: FieldBoolean, Default: false, Help: "Do not verify the server certificate. Avoid in production."},
			{Name: "allowPrivateTargets", Label: "Allow private/loopback target", Type: FieldBoolean, Default: false, Help: "Required to reach localhost or an RFC1918 address. Off by default so a webhook cannot be pointed at internal services; enable only for a relay you run yourself."},
		},
		Decode: decodeTyped[WebhookConfig](),
		Build: func(cfg any) (ChannelSender, error) {
			return buildWebhook(*cfg.(*WebhookConfig))
		},
	},
	ChannelEmail: {
		Type:         ChannelEmail,
		Description:  "Email to a list of recipients via SMTP",
		HasSecret:    true,
		SecretFields: []string{"password"},
		Fields: []FieldSpec{
			{Name: "host", Label: "SMTP host", Type: FieldString, Required: true, Placeholder: "smtp.example.com", Help: "SMTP relay host."},
			{Name: "port", Label: "SMTP port", Type: FieldInteger, Default: 587, Help: "587 = STARTTLS, 465 = implicit TLS, 25 = plaintext."},
			{Name: "username", Label: "Username", Type: FieldString},
			{Name: "password", Label: "Password", Type: FieldSecret},
			{Name: "from", Label: "From address", Type: FieldString, Required: true, Placeholder: "osctrl@example.com", Help: "Envelope sender for the notification."},
			{Name: "to", Label: "Recipients", Type: FieldString, Required: true, Placeholder: "soc@example.com, oncall@example.com", Help: "Comma-separated recipient addresses."},
			{Name: "starttls", Label: "Use STARTTLS", Type: FieldBoolean, Default: true, Help: "Upgrade to TLS after connect (port 587). Ignored on port 465 (implicit TLS)."},
		},
		Decode: decodeTyped[EmailConfig](),
		Build: func(cfg any) (ChannelSender, error) {
			return buildEmail(*cfg.(*EmailConfig))
		},
	},
}

// TestSendTimeout bounds a channel test so an unresponsive relay cannot
// hold the API request open. Senders carry their own per-request
// timeouts; this is the backstop for the ones that do not (SMTP).
const TestSendTimeout = 15 * time.Second

// TestSend delivers one synthetic notification through a channel config
// without storing it, so an operator can verify a channel from the form
// before saving. Config errors and delivery errors are both returned as
// they are — the operator needs to see which relay refused what.
func TestSend(typ, cfgJSON string) error {
	spec, ok := ChannelRegistry[normalizeChannelType(typ)]
	if !ok {
		return fmt.Errorf("%w: %q", ErrInvalidChannelType, typ)
	}
	if strings.TrimSpace(cfgJSON) == "" {
		cfgJSON = "{}"
	}
	decoded, err := spec.Decode(json.RawMessage(cfgJSON))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidChannelConfig, err)
	}
	sender, err := spec.Build(decoded)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidChannelConfig, err)
	}
	// Buffered by one so an abandoned send finishes into the channel and
	// the goroutine exits instead of leaking on timeout.
	done := make(chan error, 1)
	go func() { done <- sender.Send(TestHit()) }()
	select {
	case err := <-done:
		return err
	case <-time.After(TestSendTimeout):
		return fmt.Errorf("channel test timed out after %s", TestSendTimeout)
	}
}

// TestHit is the payload a channel test delivers. It is shaped like a
// real hit so the operator sees exactly the format their relay will
// receive, and is labelled so nobody mistakes it for a live alert.
func TestHit() Hit {
	return Hit{
		RuleName:    "osctrl-channel-test",
		Environment: "osctrl",
		Entity:      "channel-test",
		Detail:      "Test notification from osctrl. If you are reading this, the channel works.",
	}
}

// FieldSpec reuses the logsinks field schema for SPA form rendering.
type FieldSpec struct {
	Name        string
	Label       string
	Type        string // string | integer | boolean | secret
	Required    bool
	Placeholder string
	Help        string
	Default     any
}

// Field types for channel forms.
const (
	FieldString  = "string"
	FieldInteger = "integer"
	FieldBoolean = "boolean"
	FieldSecret  = "secret"
)

// SupportedChannelTypes lists the registry keys, sorted.
func SupportedChannelTypes() []string {
	out := make([]string, 0, len(ChannelRegistry))
	for k := range ChannelRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ValidateChannelType reports whether the type is registered.
func ValidateChannelType(typ string) bool {
	_, ok := ChannelRegistry[normalizeChannelType(typ)]
	return ok
}

// ValidateChannelConfig decodes the JSON config against the registry.
func ValidateChannelConfig(typ, cfgJSON string) error {
	spec, ok := ChannelRegistry[normalizeChannelType(typ)]
	if !ok {
		return fmt.Errorf("%w: %q", ErrInvalidChannelType, typ)
	}
	if cfgJSON == "" {
		cfgJSON = "{}"
	}
	if _, err := spec.Decode(json.RawMessage(cfgJSON)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidChannelConfig, err)
	}
	return nil
}

// ErrInvalidChannelType is returned for unregistered channel types.
var ErrInvalidChannelType = fmt.Errorf("invalid channel type")

// ErrInvalidChannelConfig is returned when the config JSON fails to
// decode against the registered type.
var ErrInvalidChannelConfig = fmt.Errorf("invalid channel configuration")

func normalizeChannelType(typ string) string {
	return strings.ToLower(strings.TrimSpace(typ))
}

// decodeTyped returns a Decode func that unmarshals raw JSON into a
// fresh T (logsinks pattern).
func decodeTyped[T any]() func(json.RawMessage) (any, error) {
	return func(raw json.RawMessage) (any, error) {
		var cfg T
		if len(raw) == 0 || string(raw) == "null" {
			return &cfg, nil
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("decode %T: %w", cfg, err)
		}
		return &cfg, nil
	}
}

// secretPlaceholder is what redacted secret fields read back as.
const secretPlaceholder = "***"

// RedactedChannelConfig returns the Config JSON with secret fields
// replaced by "***" for the channel Type. Non-secret types return the
// raw config unchanged. Best-effort: undecodable configs pass through.
func RedactedChannelConfig(typ, cfgJSON string) string {
	spec, ok := ChannelRegistry[normalizeChannelType(typ)]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return cfgJSON
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &obj); err != nil {
		return cfgJSON
	}
	for _, key := range spec.SecretFields {
		if _, present := obj[key]; present {
			obj[key] = secretPlaceholder
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return cfgJSON
	}
	return string(out)
}

// MergeChannelSecrets replaces "***" placeholder values in newCfg with
// the corresponding values from prevCfg, so an API update that did not
// touch a secret preserves the stored one instead of writing the
// placeholder.
func MergeChannelSecrets(typ, prevCfgJSON, newCfgJSON string) (string, error) {
	spec, ok := ChannelRegistry[normalizeChannelType(typ)]
	if !ok || !spec.HasSecret || len(spec.SecretFields) == 0 {
		return newCfgJSON, nil
	}
	var prev, next map[string]any
	if err := json.Unmarshal([]byte(prevCfgJSON), &prev); err != nil {
		return "", fmt.Errorf("decode prev config: %w", err)
	}
	if err := json.Unmarshal([]byte(newCfgJSON), &next); err != nil {
		return "", fmt.Errorf("decode new config: %w", err)
	}
	for _, key := range spec.SecretFields {
		v, ok := next[key]
		if !ok {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		if s == secretPlaceholder || s == "" {
			if pv, pok := prev[key]; pok {
				next[key] = pv
			}
		}
	}
	out, err := json.Marshal(next)
	if err != nil {
		return "", fmt.Errorf("encode merged config: %w", err)
	}
	return string(out), nil
}
