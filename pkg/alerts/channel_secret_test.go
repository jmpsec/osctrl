package alerts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const secretToken = "TOPSECRETTOKEN"

func TestWebhookSendErrorOmitsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	target := srv.URL + "/services/" + secretToken
	srv.Close() // connection refused
	sender, err := buildWebhook(WebhookConfig{URL: target, AllowPrivateTargets: true, TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send(Hit{RuleName: "r"})
	if err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(err.Error(), secretToken) || strings.Contains(err.Error(), "/services/") {
		t.Fatalf("error leaks the webhook URL: %v", err)
	}
}

func TestWebhookParseErrorOmitsURL(t *testing.T) {
	_, err := buildWebhook(WebhookConfig{URL: "http://exa mple.com/" + secretToken})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("error leaks the webhook URL: %v", err)
	}
}

func TestWebhookHostOnlyMessagesUnchanged(t *testing.T) {
	_, err := buildWebhook(WebhookConfig{URL: "http://127.0.0.1:9/" + secretToken})
	if err == nil || !strings.Contains(err.Error(), "allowPrivateTargets") || !strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("unexpected SSRF message: %v", err)
	}
	_, err = buildWebhook(WebhookConfig{URL: "ftp://example.com/x"})
	if err == nil || !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Fatalf("unexpected scheme message: %v", err)
	}
}

func TestWebhookSecretFields(t *testing.T) {
	spec := ChannelRegistry[ChannelWebhook]
	if strings.Join(spec.SecretFields, ",") != "url,secret" {
		t.Fatalf("SecretFields = %v", spec.SecretFields)
	}
	for _, f := range spec.Fields {
		if f.Name == "url" && (f.Type != FieldSecret || !f.Required) {
			t.Fatalf("url field = %+v", f)
		}
	}
}

func TestRedactedChannelConfigWebhook(t *testing.T) {
	out := RedactedChannelConfig(ChannelWebhook, `{"url":"https://h/x","secret":"s","timeoutSeconds":5}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["url"] != "***" || m["secret"] != "***" || m["timeoutSeconds"] != float64(5) {
		t.Fatalf("redacted = %v", m)
	}
	// absent secret fields are not invented
	out = RedactedChannelConfig(ChannelWebhook, `{"url":"https://h/x"}`)
	if strings.Contains(out, "secret") || strings.Contains(out, "https://h/x") {
		t.Fatalf("redacted = %s", out)
	}
	// undecodable passes through
	if got := RedactedChannelConfig(ChannelWebhook, `{bad`); got != `{bad` {
		t.Fatalf("got %s", got)
	}
}

func TestMergeChannelSecretsWebhookURL(t *testing.T) {
	prev := `{"url":"https://h/real","secret":"s3"}`
	get := func(cfg, k string) any {
		var m map[string]any
		if err := json.Unmarshal([]byte(cfg), &m); err != nil {
			t.Fatal(err)
		}
		return m[k]
	}
	for _, in := range []string{`{"url":"***","secret":"***"}`, `{"url":"","secret":""}`} {
		out, err := MergeChannelSecrets(ChannelWebhook, prev, in)
		if err != nil {
			t.Fatal(err)
		}
		if get(out, "url") != "https://h/real" || get(out, "secret") != "s3" {
			t.Fatalf("%s -> %s", in, out)
		}
	}
	out, _ := MergeChannelSecrets(ChannelWebhook, prev, `{"url":"https://h/new","secret":"***"}`)
	if get(out, "url") != "https://h/new" || get(out, "secret") != "s3" {
		t.Fatalf("new url -> %s", out)
	}
	// absent url untouched
	out, _ = MergeChannelSecrets(ChannelWebhook, prev, `{"secret":"***"}`)
	if get(out, "url") != nil {
		t.Fatalf("absent url invented: %s", out)
	}
	// no previous value: placeholder stays
	out, _ = MergeChannelSecrets(ChannelWebhook, `{}`, `{"url":"***"}`)
	if get(out, "url") != "***" {
		t.Fatalf("got %s", out)
	}
	// undecodable JSON errors
	if _, err := MergeChannelSecrets(ChannelWebhook, `{bad`, `{"url":"***"}`); err == nil {
		t.Fatal("expected error for undecodable prev")
	}
	if _, err := MergeChannelSecrets(ChannelWebhook, prev, `{bad`); err == nil {
		t.Fatal("expected error for undecodable new")
	}
}
