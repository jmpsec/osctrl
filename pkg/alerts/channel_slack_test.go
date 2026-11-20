package alerts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeSlack serves the Web API methods the channel calls and records forms.
func fakeSlack(t *testing.T, user string) chan url.Values {
	t.Helper()
	calls := make(chan url.Values, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer xoxb-test", r.Header.Get("Authorization"))
		require.NoError(t, r.ParseForm())
		calls <- r.PostForm
		switch r.URL.Path {
		case "/chat.postMessage":
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/users.info":
			_, _ = w.Write([]byte(user))
		default:
			_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
		}
	}))
	t.Cleanup(srv.Close)
	prev := SlackAPIBase
	SlackAPIBase = srv.URL
	t.Cleanup(func() { SlackAPIBase = prev })
	return calls
}

func TestSlackSend(t *testing.T) {
	calls := fakeSlack(t, "")
	h := Hit{RuleName: "Santa approval request", Environment: "dev", Detail: "<!channel> asks & <https://evil|click>",
		Actions: []HitAction{{ID: "santa_approve", Label: "Approve", Value: "v", Style: "primary"}}}
	for _, tt := range []struct {
		name    string
		secret  string
		buttons bool
	}{
		{"no signing secret, no buttons", "", false},
		{"buttons", "s3cret", true},
	} {
		s, err := buildSlack(SlackConfig{Token: "xoxb-test", Channel: "C1", SigningSecret: tt.secret})
		require.NoError(t, err)
		require.NoError(t, s.Send(h), tt.name)
		form := <-calls
		require.Equal(t, "C1", form.Get("channel"))
		blocks := form.Get("blocks")
		require.NotContains(t, blocks, "<!channel>", tt.name)
		require.NotContains(t, form.Get("text"), "<!channel>", tt.name)
		require.Contains(t, blocks, "\\u0026lt;!channel\\u0026gt; asks \\u0026amp;", tt.name)
		require.Equal(t, tt.buttons, strings.Contains(blocks, `"action_id":"santa_approve"`), tt.name)
	}
	_, err := buildSlack(SlackConfig{Channel: "C1"})
	require.Error(t, err)
}

func TestVerifySlackSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := []byte("payload=%7B%7D")
	sign := func(secret string, ts int64, b []byte) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte("v0:" + strconv.FormatInt(ts, 10) + ":"))
		mac.Write(b)
		return "v0=" + hex.EncodeToString(mac.Sum(nil))
	}
	ts := now.Unix()
	for _, tt := range []struct {
		name   string
		secret string
		ts     string
		sig    string
		body   []byte
		ok     bool
	}{
		{"valid", "s", strconv.FormatInt(ts, 10), sign("s", ts, body), body, true},
		{"wrong secret", "s", strconv.FormatInt(ts, 10), sign("other", ts, body), body, false},
		{"body changed", "s", strconv.FormatInt(ts, 10), sign("s", ts, body), []byte("payload=x"), false},
		{"replayed after 6 minutes", "s", strconv.FormatInt(ts-360, 10), sign("s", ts-360, body), body, false},
		{"from the future", "s", strconv.FormatInt(ts+360, 10), sign("s", ts+360, body), body, false},
		{"no timestamp", "s", "", sign("s", ts, body), body, false},
		{"no secret configured", "", strconv.FormatInt(ts, 10), sign("", ts, body), body, false},
	} {
		err := VerifySlackSignature(tt.secret, tt.ts, tt.sig, tt.body, now)
		require.Equal(t, tt.ok, err == nil, tt.name)
	}
}

func TestSlackUserEmail(t *testing.T) {
	for _, tt := range []struct {
		name  string
		user  string
		email string
	}{
		{"confirmed", `{"ok":true,"user":{"is_email_confirmed":true,"profile":{"email":"erin@example.com"}}}`, "erin@example.com"},
		{"unconfirmed", `{"ok":true,"user":{"is_email_confirmed":false,"profile":{"email":"erin@example.com"}}}`, ""},
		{"bot", `{"ok":true,"user":{"is_bot":true,"profile":{"email":"bot@example.com"}}}`, ""},
		{"deleted", `{"ok":true,"user":{"deleted":true,"profile":{"email":"erin@example.com"}}}`, ""},
		{"missing scope", `{"ok":false,"error":"missing_scope"}`, ""},
	} {
		calls := fakeSlack(t, tt.user)
		email, err := SlackUserEmail("xoxb-test", "U1")
		require.Equal(t, "U1", (<-calls).Get("user"))
		require.Equal(t, tt.email, email, tt.name)
		require.Equal(t, tt.email == "", err != nil, tt.name)
	}
}

func TestSlackRespond(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&m))
		got <- m
	}))
	defer srv.Close()
	require.Error(t, SlackRespond(srv.URL+"/x", map[string]any{"text": "hi"}), "not a Slack hooks URL")
	prev := SlackHooksPrefix
	SlackHooksPrefix = srv.URL + "/"
	defer func() { SlackHooksPrefix = prev }()
	require.NoError(t, SlackRespond(srv.URL+"/x", map[string]any{"text": "hi"}))
	require.Equal(t, "hi", (<-got)["text"])
}

func TestSlackChannel(t *testing.T) {
	m := newTestManager(t)
	ch, err := m.CreateChannel(AlertChannel{Name: "slack", Type: ChannelSlack, Enabled: true,
		Config: `{"token":"xoxb-test","channel":"C1","signingSecret":"s"}`})
	require.NoError(t, err)
	_, cfg, err := m.SlackChannel(ch.ID)
	require.NoError(t, err)
	require.Equal(t, "s", cfg.SigningSecret)
	mail, err := m.CreateChannel(AlertChannel{Name: "mail", Type: ChannelEmail, Enabled: true,
		Config: `{"host":"smtp.example.com","from":"osctrl@example.com","to":"soc@example.com"}`})
	require.NoError(t, err)
	_, _, err = m.SlackChannel(mail.ID)
	require.Error(t, err)
	require.JSONEq(t, `{"token":"***","channel":"C1","signingSecret":"***"}`, RedactedChannelConfig(ChannelSlack, ch.Config))
}
