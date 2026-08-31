package alerts

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
		return ErrInvalidChannelType
	}
	if cfgJSON == "" {
		cfgJSON = "{}"
	}
	if _, err := spec.Decode(json.RawMessage(cfgJSON)); err != nil {
		return err
	}
	return nil
}

// ErrInvalidChannelType is returned for unregistered channel types.
var ErrInvalidChannelType = fmt.Errorf("invalid channel type")

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
