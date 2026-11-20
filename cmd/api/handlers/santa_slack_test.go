package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

// slackFake is the Slack Web API and response_url for one test.
type slackFake struct {
	posts   chan url.Values
	answers chan map[string]any
	emails  map[string]string
}

func newSlackFake(t *testing.T) *slackFake {
	t.Helper()
	f := &slackFake{posts: make(chan url.Values, 4), answers: make(chan map[string]any, 4), emails: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/chat.postMessage":
			_ = r.ParseForm()
			f.posts <- r.PostForm
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/users.info":
			_ = r.ParseForm()
			email, ok := f.emails[r.PostForm.Get("user")]
			if !ok {
				_, _ = w.Write([]byte(`{"ok":false,"error":"user_not_found"}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"ok":true,"user":{"is_email_confirmed":true,"profile":{"email":%q}}}`, email)
		case "/hooks/answer":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			f.answers <- m
		}
	}))
	t.Cleanup(srv.Close)
	api, hooks := alerts.SlackAPIBase, alerts.SlackHooksPrefix
	alerts.SlackAPIBase, alerts.SlackHooksPrefix = srv.URL+"/api", srv.URL+"/hooks/"
	t.Cleanup(func() { alerts.SlackAPIBase, alerts.SlackHooksPrefix = api, hooks })
	return f
}

func (f *slackFake) answer(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-f.answers:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no answer posted to Slack")
		return nil
	}
}

// buttons returns the value of each button of the next message posted.
func (f *slackFake) buttons(t *testing.T) map[string]string {
	t.Helper()
	var form url.Values
	select {
	case form = <-f.posts:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing posted to Slack")
	}
	var blocks []struct {
		Elements []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"elements"`
	}
	require.NoError(t, json.Unmarshal([]byte(form.Get("blocks")), &blocks))
	out := map[string]string{}
	for _, b := range blocks {
		for _, e := range b.Elements {
			out[e.ActionID] = e.Value
		}
	}
	return out
}

func slackPayload(slackUser, actionID, value string) string {
	b, _ := json.Marshal(map[string]any{
		"type": "block_actions", "user": map[string]string{"id": slackUser}, "response_url": alerts.SlackHooksPrefix + "answer",
		"actions": []map[string]string{{"action_id": actionID, "value": value}},
	})
	return url.Values{"payload": {string(b)}}.Encode()
}

func slackCall(h *HandlersApi, channel uint, secret string, ts time.Time, body string) int {
	stamp := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + stamp + ":" + body))
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	r.SetPathValue("channel", strconv.FormatUint(uint64(channel), 10))
	r.Header.Set("X-Slack-Request-Timestamp", stamp)
	r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	rr := httptest.NewRecorder()
	h.SlackInteractHandler(rr, r)
	return rr.Code
}

// erin is an approver and carol a plain user, both mapped by email; dave asks.
func TestSantaSlackButtons(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	f := newSlackFake(t)
	h.Alerts = alerts.NewManager(h.DB)
	h.SantaNotify = alerts.NewDispatcher(h.Alerts)
	ch, err := h.Alerts.CreateChannel(alerts.AlertChannel{Name: "slack", Type: alerts.ChannelSlack, Enabled: true,
		Config: `{"token":"xoxb-test","channel":"C1","signingSecret":"s3cret"}`})
	require.NoError(t, err)
	require.NoError(t, h.Santa.SaveConfig(santa.EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com",
		NotifyChannels: []uint{ch.ID}, ApproverUsers: []string{"erin"}}))
	require.NoError(t, h.Users.ChangeEmail("erin", "erin@example.com"))
	require.NoError(t, h.Users.ChangeEmail("carol", "carol@example.com"))
	f.emails["UERIN"], f.emails["UCAROL"], f.emails["UNOBODY"] = "Erin@Example.com", "carol@example.com", "nobody@example.com"

	ask := func(why string) (uint, map[string]string) {
		t.Helper()
		rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, why), p)
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		var own SantaOwnRequest
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
		return own.ID, f.buttons(t)
	}
	status := func(id uint) santa.Request {
		req, err := h.Santa.Request(1, id)
		require.NoError(t, err)
		return req
	}
	now := time.Now()
	id, buttons := ask("first")
	deny := slackPayload("UERIN", slackDenyAction, buttons[slackDenyAction])

	// Forged, stale or misrouted callbacks are refused before anything is read.
	require.Equal(t, http.StatusUnauthorized, slackCall(h, ch.ID, "wrong", now, deny))
	require.Equal(t, http.StatusUnauthorized, slackCall(h, ch.ID, "s3cret", now.Add(-6*time.Minute), deny))
	require.Equal(t, http.StatusNotFound, slackCall(h, ch.ID+1, "s3cret", now, deny))
	require.Equal(t, santa.RequestPending, status(id).Status)

	// Unmapped and unauthorized Slack users cannot decide.
	for _, who := range []string{"UNOBODY", "UCAROL", "UGHOST"} {
		require.Equal(t, http.StatusOK, slackCall(h, ch.ID, "s3cret", now, slackPayload(who, slackDenyAction, buttons[slackDenyAction])), who)
		a := f.answer(t)
		require.Equal(t, "ephemeral", a["response_type"], who)
		require.Equal(t, santa.RequestPending, status(id).Status, who)
	}

	// The approver denies; the message loses its buttons.
	require.Equal(t, http.StatusOK, slackCall(h, ch.ID, "s3cret", now, deny))
	a := f.answer(t)
	require.Equal(t, true, a["replace_original"])
	require.Contains(t, a["text"], "Denied by erin in Slack.")
	req := status(id)
	require.Equal(t, []string{santa.RequestDenied, "erin", slackDenyReason}, []string{req.Status, req.DecidedBy, req.Reason})

	// The same signed callback again: the link is used up.
	require.Equal(t, http.StatusOK, slackCall(h, ch.ID, "s3cret", now, deny))
	require.Equal(t, "ephemeral", f.answer(t)["response_type"])

	// Approve allows the file on the requester's machine only.
	id, buttons = ask("second")
	require.Equal(t, http.StatusOK, slackCall(h, ch.ID, "s3cret", now, slackPayload("UERIN", slackApproveAction, buttons[slackApproveAction])))
	require.Contains(t, f.answer(t)["text"], "Approved for this machine by erin")
	req = status(id)
	require.Equal(t, santa.RequestApproved, req.Status)
	rules, err := h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.Equal(t, "node", rules[0].Scope)

	// A button for another action, or from another app, is ignored.
	require.Equal(t, http.StatusOK, slackCall(h, ch.ID, "s3cret", now, slackPayload("UERIN", "other", "x")))
	select {
	case m := <-f.answers:
		t.Fatalf("unexpected answer %v", m)
	case <-time.After(100 * time.Millisecond):
	}
}
