package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

type fakeNotifier chan alerts.Hit

func (f fakeNotifier) Dispatch(_ context.Context, h alerts.Hit) error {
	f <- h
	return nil
}

func (f fakeNotifier) next(t *testing.T) alerts.Hit {
	t.Helper()
	select {
	case h := <-f:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no notification was sent")
		return alerts.Hit{}
	}
}

func (f fakeNotifier) none(t *testing.T) {
	t.Helper()
	select {
	case h := <-f:
		t.Fatalf("unexpected notification: %+v", h)
	case <-time.After(100 * time.Millisecond):
	}
}

func webhookChannel(t *testing.T, m *alerts.Manager, name string, envID uint) alerts.AlertChannel {
	t.Helper()
	ch, err := m.CreateChannel(alerts.AlertChannel{
		Name: name, EnvironmentID: envID, Type: alerts.ChannelWebhook, Enabled: true, Config: `{"url":"https://hooks.example.com/x"}`,
	})
	require.NoError(t, err)
	return ch
}

func TestSantaConfigNotifyChannels(t *testing.T) {
	h, db, envA, envB := setupSantaHandlers(t)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	p := map[string]string{"env": envA.Name}
	put := func(user, channels string) int {
		body := fmt.Sprintf(`{"client_mode":"LOCKDOWN","approval_url":"https://osctrl.example.com","notify_channels":%s}`, channels)
		return santaDo(h.SantaConfigPutHandler, "PUT", user, body, p).Code
	}

	// Without alerts there is nothing to point at.
	require.Equal(t, http.StatusBadRequest, put("root", "[1]"))

	h.Alerts = alerts.NewManager(db)
	global := webhookChannel(t, h.Alerts, "global", alerts.NoEnvironmentID)
	own := webhookChannel(t, h.Alerts, "own", envA.ID)
	other := webhookChannel(t, h.Alerts, "other", envB.ID)
	both := fmt.Sprintf("[%d,%d]", own.ID, global.ID)

	tests := []struct {
		name, user, channels string
		code                 int
	}{
		{"environment admin cannot set channels", "alice", both, http.StatusForbidden},
		{"another environment's channel", "root", fmt.Sprintf("[%d]", other.ID), http.StatusBadRequest},
		{"unknown channel", "root", "[9999]", http.StatusBadRequest},
		{"superuser sets global and own channels", "root", both, http.StatusOK},
		{"environment admin saves the config unchanged", "alice", fmt.Sprintf("[%d,%d]", global.ID, own.ID), http.StatusOK},
		{"environment admin cannot clear channels", "alice", "[]", http.StatusForbidden},
		{"environment admin cannot swap channels", "alice", fmt.Sprintf("[%d]", global.ID), http.StatusForbidden},
	}
	for _, tt := range tests {
		require.Equal(t, tt.code, put(tt.user, tt.channels), tt.name)
	}
	cfg, err := h.Santa.Config(envA.ID)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{global.ID, own.ID}, cfg.NotifyChannels)

	// Channels need the approval URL.
	rr := santaDo(h.SantaConfigPutHandler, "PUT", "root", fmt.Sprintf(`{"client_mode":"LOCKDOWN","notify_channels":%s}`, both), p)
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

var linkRe = regexp.MustCompile(`(Approve|Deny): https://osctrl\.example\.com/santa/decide/env-a\?request=(\d+)&action=(approve|deny)#(\S+)`)

func TestSantaRequestNotifyAndLink(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	notifier := make(fakeNotifier, 4)
	h.SantaNotify = notifier

	// No channels configured: nothing is sent and no link is made.
	rr := santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "first"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	notifier.none(t)
	var first SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &first))
	_, err := h.Santa.DecideRequest(1, first.ID, santa.Decision{By: "alice", Reason: "start over"})
	require.NoError(t, err)

	require.NoError(t, h.Santa.SaveConfig(santa.EnvConfig{
		EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", NotifyChannels: []uint{7, 9},
	}))
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "dave", reqBody(sha, "I need\nthis tool"), p)
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var own SantaOwnRequest
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &own))
	// The requester's answer carries no link.
	require.NotContains(t, rr.Body.String(), "decide")

	hit := notifier.next(t)
	require.Equal(t, []uint{7, 9}, hit.Channels)
	require.Equal(t, "Santa approval request", hit.RuleName)
	require.Equal(t, "a", hit.Environment)
	require.Contains(t, hit.Detail, "dave asks to allow tool (sha256 "+sha+")")
	require.Contains(t, hit.Detail, "Justification: I need this tool")
	require.NotContains(t, hit.HistoryDetail, "decide")
	require.NotContains(t, hit.HistoryDetail, "#")
	links := linkRe.FindAllStringSubmatch(hit.Detail, -1)
	require.Len(t, links, 2)
	tokens := map[string]string{}
	for _, l := range links {
		require.Equal(t, strconv.FormatUint(uint64(own.ID), 10), l[2])
		tokens[l[3]] = l[4]
	}
	require.Len(t, tokens, 2)

	// Asking again merges into the pending request: no second notification.
	rr = santaDo(h.SantaRequestCreateHandler, "POST", "erin", reqBody(sha, "me too"), p)
	require.Equal(t, http.StatusOK, rr.Code)
	notifier.none(t)

	link := func(user, env, token, decision string) int {
		body, _ := json.Marshal(map[string]string{"token": token, "decision": decision, "scope": "node", "reason": "because"})
		return santaDo(h.SantaRequestLinkHandler, "POST", user, string(body), map[string]string{"env": env}).Code
	}
	// The token alone decides nothing: the caller must be an admin of the environment.
	for _, who := range []string{"dave", "erin", "carol"} {
		require.Equal(t, http.StatusForbidden, link(who, p["env"], tokens["approve"], "approve"), who)
	}
	require.Equal(t, http.StatusForbidden, link("alice", "env-b", tokens["approve"], "approve"))
	tests := []struct {
		name, token, decision string
		code                  int
	}{
		{"unknown decision", tokens["approve"], "maybe", http.StatusBadRequest},
		{"unknown token", "nope", "approve", http.StatusGone},
		{"no token", "", "approve", http.StatusGone},
		{"approve link used to deny", tokens["approve"], "deny", http.StatusGone},
		{"approve", tokens["approve"], "approve", http.StatusOK},
		{"replay", tokens["approve"], "approve", http.StatusGone},
		{"deny link after the decision", tokens["deny"], "deny", http.StatusConflict},
	}
	for _, tt := range tests {
		require.Equal(t, tt.code, link("alice", p["env"], tt.token, tt.decision), tt.name)
	}
	rules, err := h.Santa.Rules(1)
	require.NoError(t, err)
	require.Len(t, rules, 1)

	// One request by ID, for admins of its environment only.
	one := map[string]string{"env": p["env"], "id": strconv.FormatUint(uint64(own.ID), 10)}
	rr = santaDo(h.SantaRequestGetHandler, "GET", "alice", "", one)
	require.Equal(t, http.StatusOK, rr.Code)
	var req santa.Request
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &req))
	require.Equal(t, santa.RequestApproved, req.Status)
	require.Equal(t, http.StatusForbidden, santaDo(h.SantaRequestGetHandler, "GET", "dave", "", one).Code)
	require.Equal(t, http.StatusNotFound, santaDo(h.SantaRequestGetHandler, "GET", "alice", "", map[string]string{"env": p["env"], "id": "9999"}).Code)
	require.Equal(t, http.StatusBadRequest, santaDo(h.SantaRequestGetHandler, "GET", "alice", "", map[string]string{"env": p["env"], "id": "x"}).Code)
}
