package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strings"
	"sync"
	"testing"
)

// ─────────────────────────────── webhook ───────────────────────────────

func TestWebhookDeliversAndSigns(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	var sigs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		sigs = append(sigs, r.Header.Get(SignatureHeader))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, err := buildWebhook(WebhookConfig{URL: srv.URL, Secret: "s3cret", AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("buildWebhook: %v", err)
	}
	hit := Hit{RuleName: "sudoers", RuleID: 1, Environment: "prod", NodeUUID: "U", Entity: "U:q", Detail: "/etc/sudoers"}
	if err := sender.Send(hit); err != nil {
		t.Fatalf("Send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("expected 1 delivery, got %d", len(bodies))
	}
	// HMAC must verify against the received body.
	if !hmacEqual("s3cret", bodies[0], sigs[0]) {
		t.Fatalf("signature does not verify: %q", sigs[0])
	}
	var payload webhookPayload
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload.Rule != "sudoers" || payload.Environment != "prod" || payload.Detail != "/etc/sudoers" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func hmacEqual(secret string, body []byte, hexSig string) bool {
	if hexSig == "" {
		return false
	}
	return hmacHex(secret, body) == hexSig
}

func TestWebhookNoSecretNoHeader(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, err := buildWebhook(WebhookConfig{URL: srv.URL, AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("buildWebhook: %v", err)
	}
	if err := sender.Send(Hit{RuleName: "r"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got != "" {
		t.Fatalf("signature header present without secret: %q", got)
	}
}

func TestWebhookRetriesOn500(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender, err := buildWebhook(WebhookConfig{URL: srv.URL, AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("buildWebhook: %v", err)
	}
	err = sender.Send(Hit{RuleName: "r"})
	if err == nil {
		t.Fatal("expected failure after retries")
	}
	if attempts != webhookMaxRetries {
		t.Fatalf("expected %d attempts, got %d", webhookMaxRetries, attempts)
	}
}

func TestWebhookNoRetryOn4xx(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	sender, err := buildWebhook(WebhookConfig{URL: srv.URL, AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("buildWebhook: %v", err)
	}
	if err := sender.Send(Hit{RuleName: "r"}); err == nil {
		t.Fatal("expected failure on 403")
	}
	if attempts != 1 {
		t.Fatalf("4xx must not retry, attempts = %d", attempts)
	}
}

func TestWebhookSSRFGuard(t *testing.T) {
	cases := []struct {
		name string
		url  string
		ok   bool
	}{
		{"loopback", "http://127.0.0.1:9000/hook", false},
		{"localhost", "http://localhost:9000/hook", false},
		{"private-ipv4", "http://192.168.1.10/hook", false},
		{"link-local", "http://169.254.1.1/hook", false},
		{"unresolvable-refused", "https://no-such-host.invalid/hook", false},
		{"loopback-allowed", "http://127.0.0.1:9000/hook", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildWebhook(WebhookConfig{URL: c.url, AllowPrivateTargets: c.ok})
			if c.ok && err != nil {
				t.Fatalf("allowPrivateTargets=true must build: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("expected SSRF rejection")
			}
		})
	}
}

func TestWebhookBadConfig(t *testing.T) {
	if _, err := buildWebhook(WebhookConfig{}); err == nil {
		t.Fatal("empty URL must fail")
	}
	if _, err := buildWebhook(WebhookConfig{URL: "ftp://example.com"}); err == nil {
		t.Fatal("non-http scheme must fail")
	}
}

// ─────────────────────────────── email ───────────────────────────────

func TestEmailRender(t *testing.T) {
	sender, err := buildEmail(EmailConfig{
		Host: "smtp.example.com", Port: 587, From: "osctrl@example.com", To: "soc@example.com, oncall@example.com", StartTLS: true,
	})
	if err != nil {
		t.Fatalf("buildEmail: %v", err)
	}
	es := sender.(*emailSender)
	es.send = func(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
		if addr != "smtp.example.com:587" {
			t.Fatalf("addr: %s", addr)
		}
		if from != "osctrl@example.com" {
			t.Fatalf("from: %s", from)
		}
		if len(to) != 2 || to[0] != "soc@example.com" || to[1] != "oncall@example.com" {
			t.Fatalf("recipients: %+v", to)
		}
		body := string(msg)
		if !strings.Contains(body, "Subject: [osctrl] alert: rule-x (env prod)") {
			t.Fatalf("subject missing: %s", body)
		}
		if !strings.Contains(body, "Node:        U-1") {
			t.Fatalf("node line missing: %s", body)
		}
		return nil
	}
	if err := sender.Send(Hit{RuleName: "rule-x", Environment: "prod", NodeUUID: "U-1", Entity: "e", Detail: "d"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestEmailBadConfig(t *testing.T) {
	if _, err := buildEmail(EmailConfig{From: "a@b", To: "c@d"}); err == nil {
		t.Fatal("missing host must fail")
	}
	if _, err := buildEmail(EmailConfig{Host: "h", From: "notanemail", To: "c@d"}); err == nil {
		t.Fatal("invalid from must fail")
	}
	if _, err := buildEmail(EmailConfig{Host: "h", From: "a@b"}); err == nil {
		t.Fatal("missing recipients must fail")
	}
}

// ─────────────────────────────── registry ───────────────────────────────

func TestChannelRegistryComplete(t *testing.T) {
	types := SupportedChannelTypes()
	if len(types) != 2 || types[0] != ChannelEmail || types[1] != ChannelWebhook {
		t.Fatalf("registry types: %v", types)
	}
	if !ValidateChannelType("WEBHOOK") || !ValidateChannelType(" email ") {
		t.Fatal("type validation must normalize")
	}
	if ValidateChannelType("pigeon") {
		t.Fatal("unknown type must fail")
	}
	if err := ValidateChannelConfig(ChannelWebhook, `{"url":"https://x.example.com"}`); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := ValidateChannelConfig(ChannelWebhook, `{not json`); err == nil {
		t.Fatal("invalid JSON must fail")
	}
	if err := ValidateChannelConfig("pigeon", `{}`); err == nil {
		t.Fatal("unknown type must fail validation")
	}
}

// ─────────────────────────────── dispatcher ───────────────────────────────

func TestDispatcherFanOutIsolation(t *testing.T) {
	m := newTestManager(t)
	good, err := m.CreateChannel(AlertChannel{
		Name: "good", Type: ChannelWebhook, Enabled: true,
		Config: `{"url":"` + goodWebhookURL(t) + `","allowPrivateTargets":true}`,
	})
	if err != nil {
		t.Fatalf("create good channel: %v", err)
	}
	bad, err := m.CreateChannel(AlertChannel{
		Name: "bad", Type: ChannelWebhook, Enabled: true,
		Config: `{"url":"http://127.0.0.1:1/unreachable","allowPrivateTargets":true}`,
	})
	if err != nil {
		t.Fatalf("create bad channel: %v", err)
	}

	d := NewDispatcher(m)
	h := Hit{RuleName: "r", RuleID: 1, Environment: "dev", NodeUUID: "U", Entity: "e", Detail: "d", Channels: []uint{good.ID, bad.ID}}
	err = d.Dispatch(context.Background(), h)
	if err != nil {
		t.Fatalf("one live channel must not fail the dispatch: %v", err)
	}
	// History must attribute only the successful channel.
	rows, _ := m.RecentHistory(10)
	if len(rows) != 1 || rows[0].ChannelName != "good" {
		t.Fatalf("history should record only good channel: %+v", rows)
	}
}

func goodWebhookURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	// httptest binds 127.0.0.1 — the guard would reject it; the
	// dispatcher builds from the raw config so patch the URL with the
	// private-target opt-in.
	return srv.URL
}

func TestDispatcherAllChannelsFail(t *testing.T) {
	m := newTestManager(t)
	ch, err := m.CreateChannel(AlertChannel{
		Name: "dead", Type: ChannelWebhook, Enabled: true,
		Config: `{"url":"http://127.0.0.1:1/unreachable","allowPrivateTargets":true}`,
	})
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	d := NewDispatcher(m)
	h := Hit{RuleName: "r", Channels: []uint{ch.ID}}
	if err := d.Dispatch(context.Background(), h); err == nil {
		t.Fatal("all-failed dispatch must error so the worker retries")
	}
}

func TestDispatcherDisabledAndUnknownChannels(t *testing.T) {
	m := newTestManager(t)
	disabled, err := m.CreateChannel(AlertChannel{
		Name: "off", Type: ChannelWebhook, Enabled: false,
		Config: `{"url":"https://x.example.com/hook"}`,
	})
	if err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	// A row with an unknown type cannot be created through the manager
	// (validation), so simulate one written by an older version / direct
	// DB edit — the dispatcher must skip it, not crash.
	unknown := AlertChannel{Name: "weird", Type: "pigeon", Enabled: true, Config: `{"coo":"true"}`}
	if err := m.DB.Create(&unknown).Error; err != nil {
		t.Fatalf("seed unknown channel: %v", err)
	}

	d := NewDispatcher(m)
	// Zero usable channels: not an error (nothing to send).
	h := Hit{RuleName: "r", Channels: []uint{disabled.ID, unknown.ID, 99999}}
	if err := d.Dispatch(context.Background(), h); err != nil {
		t.Fatalf("unusable channels should no-op: %v", err)
	}
	rows, _ := m.RecentHistory(10)
	if len(rows) != 0 {
		t.Fatalf("no history expected: %+v", rows)
	}
}

// TestDispatcherCacheRebuild verifies the sender cache is keyed on the
// config: editing a channel invalidates the cache.
func TestDispatcherCacheRebuild(t *testing.T) {
	m := newTestManager(t)
	url := goodWebhookURL(t)
	ch, err := m.CreateChannel(AlertChannel{
		Name: "c", Type: ChannelWebhook, Enabled: true,
		Config: `{"url":"` + url + `","allowPrivateTargets":true}`,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	d := NewDispatcher(m)
	h := Hit{RuleName: "r", Channels: []uint{ch.ID}}
	if err := d.Dispatch(context.Background(), h); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	// Break the channel (unreachable private URL — opt-in kept).
	updated := ch
	updated.Config = `{"url":"http://127.0.0.1:1/x","allowPrivateTargets":true}`
	if _, err := m.UpdateChannel(ch.ID, updated); err != nil {
		t.Fatalf("update: %v", err)
	}
	d.RefreshChannel(ch.ID)
	if err := d.Dispatch(context.Background(), h); err == nil {
		t.Fatal("rebuilt sender against the dead URL must fail")
	}
}
