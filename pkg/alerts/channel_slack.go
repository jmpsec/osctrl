package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// channel_slack.go — Slack channel: Block Kit messages posted with a bot
// token (chat.postMessage), with buttons when the hit has actions and the
// channel has the Slack app's signing secret to verify the button callbacks.

// SlackConfig is the typed JSON config for Slack channels.
type SlackConfig struct {
	// Bot token (xoxb-) with chat:write, and users:read.email for buttons
	Token string `json:"token"`
	// Channel ID the messages are posted to
	Channel string `json:"channel"`
	// Signing secret of the Slack app; buttons are sent only when it is set
	SigningSecret string `json:"signingSecret"`
}

// HitAction is a button on a notification, for channels that have them.
type HitAction struct {
	// Returned in the callback as action_id
	ID    string
	Label string
	// Returned in the callback; may carry a secret
	Value string
	// primary, danger or empty
	Style string
}

// SlackAPIBase and SlackHooksPrefix are the Slack Web API and the only
// prefix accepted for a callback's response_url; tests point them elsewhere.
var (
	SlackAPIBase     = "https://slack.com/api"
	SlackHooksPrefix = "https://hooks.slack.com/"
)

// SlackMaxSkew is how old (or how far in the future) a callback timestamp
// may be, as Slack recommends.
const SlackMaxSkew = 5 * time.Minute

var slackClient = &http.Client{Timeout: 10 * time.Second}

type slackSender struct{ cfg SlackConfig }

func buildSlack(cfg SlackConfig) (ChannelSender, error) {
	switch {
	case cfg.Token == "":
		return nil, fmt.Errorf("slack bot token is required")
	case cfg.Channel == "":
		return nil, fmt.Errorf("slack channel ID is required")
	}
	return &slackSender{cfg: cfg}, nil
}

func (s *slackSender) Name() string { return ChannelSlack }

// Send posts the hit. Hit text is written by users and clients, so it is
// escaped: it cannot mention @channel or make links.
func (s *slackSender) Send(h Hit) error {
	text := "*" + SlackEscape(h.RuleName) + "*"
	if h.Environment != "" {
		text += " (env " + SlackEscape(h.Environment) + ")"
	}
	text += "\n" + SlackEscape(h.Detail)
	blocks := []map[string]any{{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": truncate(text, 3000)}}}
	if len(h.Actions) > 0 && s.cfg.SigningSecret != "" {
		var buttons []map[string]any
		for _, a := range h.Actions {
			b := map[string]any{"type": "button", "action_id": a.ID, "value": a.Value,
				"text": map[string]any{"type": "plain_text", "text": a.Label}}
			if a.Style != "" {
				b["style"] = a.Style
			}
			buttons = append(buttons, b)
		}
		blocks = append(blocks, map[string]any{"type": "actions", "elements": buttons})
	}
	b, err := json.Marshal(blocks)
	if err != nil {
		return err
	}
	return slackCall(s.cfg.Token, "chat.postMessage", url.Values{
		"channel": {s.cfg.Channel}, "text": {truncate(SlackEscape(h.RuleName+": "+h.Detail), 3000)}, "blocks": {string(b)},
	}, nil)
}

// slackCall calls a Web API method and decodes the answer into out.
func slackCall(token, method string, form url.Values, out any) error {
	req, err := http.NewRequest(http.MethodPost, SlackAPIBase+"/"+method, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := slackClient.Do(req)
	if err != nil {
		return stripURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("slack %s: status %d", method, resp.StatusCode)
	}
	if !res.OK {
		return fmt.Errorf("slack %s: %s", method, res.Error)
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

// VerifySlackSignature checks a callback against the app's signing secret:
// the v0 HMAC of the timestamp and body, with a timestamp within SlackMaxSkew
// of now so a captured callback cannot be sent again later.
func VerifySlackSignature(secret, timestamp, signature string, body []byte, now time.Time) error {
	if secret == "" {
		return errors.New("no signing secret")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > SlackMaxSkew || d < -SlackMaxSkew {
		return errors.New("stale timestamp")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + timestamp + ":"))
	mac.Write(body)
	if !hmac.Equal([]byte("v0="+hex.EncodeToString(mac.Sum(nil))), []byte(signature)) {
		return errors.New("bad signature")
	}
	return nil
}

// SlackUserEmail returns the email of a Slack user, which Slack verifies.
// Bots, deleted users and users without a confirmed email get an error.
func SlackUserEmail(token, userID string) (string, error) {
	var res struct {
		User struct {
			Deleted          bool  `json:"deleted"`
			IsBot            bool  `json:"is_bot"`
			IsEmailConfirmed *bool `json:"is_email_confirmed"`
			Profile          struct {
				Email string `json:"email"`
			} `json:"profile"`
		} `json:"user"`
	}
	if err := slackCall(token, "users.info", url.Values{"user": {userID}}, &res); err != nil {
		return "", err
	}
	u := res.User
	if u.Deleted || u.IsBot || u.Profile.Email == "" || (u.IsEmailConfirmed != nil && !*u.IsEmailConfirmed) {
		return "", errors.New("slack user has no confirmed email")
	}
	return u.Profile.Email, nil
}

// SlackRespond posts a message to a callback's response_url, which must be a
// Slack hooks URL.
func SlackRespond(responseURL string, msg any) error {
	if !strings.HasPrefix(responseURL, SlackHooksPrefix) {
		return errors.New("response_url is not a Slack hooks URL")
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := slackClient.Post(responseURL, "application/json", bytes.NewReader(b))
	if err != nil {
		return stripURLError(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack response_url status %d", resp.StatusCode)
	}
	return nil
}

// SlackChannel returns an enabled Slack channel and its config.
func (m *Manager) SlackChannel(id uint) (AlertChannel, SlackConfig, error) {
	var cfg SlackConfig
	ch, err := m.GetChannel(id)
	switch {
	case err != nil:
		return ch, cfg, err
	case normalizeChannelType(ch.Type) != ChannelSlack:
		return ch, cfg, errors.New("not a slack channel")
	case !ch.Enabled:
		return ch, cfg, ErrChannelDisabled
	}
	return ch, cfg, json.Unmarshal([]byte(ch.Config), &cfg)
}

// SlackEscape escapes the three characters Slack gives meaning to, so text
// written by users cannot mention anyone or make links.
func SlackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// truncate cuts s to at most n runes.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
