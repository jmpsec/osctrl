package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/alerts"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/rs/zerolog/log"
)

// Slack button action IDs on approval request notifications.
const (
	slackApproveAction = "santa_approve"
	slackDenyAction    = "santa_deny"
	slackMaxBody       = 64 << 10
	// slackDenyReason is the reason of a denial from Slack, which has no form.
	slackDenyReason = "Denied in Slack"
)

// slackInteraction is the part of a Slack interaction payload osctrl reads.
type slackInteraction struct {
	Type string `json:"type"`
	User struct {
		ID string `json:"id"`
	} `json:"user"`
	ResponseURL string `json:"response_url"`
	Actions     []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

// SlackInteractHandler — POST /api/v1/slack/interact/{channel}
// @Summary Slack button callback for Santa approval requests
// @Description Called by Slack, not by users: authenticated by the signing secret of the Slack alert channel in the path, with a timestamp at most 5 minutes old. The Slack user is matched by their Slack-verified email to exactly one osctrl user, who must be an environment admin or approver. Each button carries a single-use link token. The result is posted to the callback's response_url.
// @Tags santa
// @Accept x-www-form-urlencoded
// @Param channel path int true "Slack alert channel ID"
// @Success 200
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 401 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Router /api/v1/slack/interact/{channel} [post]
func (h *HandlersApi) SlackInteractHandler(w http.ResponseWriter, r *http.Request) {
	if h.Santa == nil || h.Alerts == nil {
		apiErrorResponse(w, "santa or alerts not enabled", http.StatusServiceUnavailable, nil)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("channel"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "channel not found", http.StatusNotFound, err)
		return
	}
	ch, cfg, err := h.Alerts.SlackChannel(uint(id))
	if err != nil {
		apiErrorResponse(w, "channel not found", http.StatusNotFound, err)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, slackMaxBody))
	if err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	if err := alerts.VerifySlackSignature(cfg.SigningSecret, r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature"), body, time.Now()); err != nil {
		apiErrorResponse(w, "invalid signature", http.StatusUnauthorized, err)
		return
	}
	form, err := url.ParseQuery(string(body))
	var p slackInteraction
	if err == nil {
		err = json.Unmarshal([]byte(form.Get("payload")), &p)
	}
	if err != nil {
		apiErrorResponse(w, "invalid payload", http.StatusBadRequest, err)
		return
	}
	// Other interactions (and other apps' buttons) are acknowledged and ignored.
	if p.Type != "block_actions" || len(p.Actions) != 1 ||
		(p.Actions[0].ActionID != slackApproveAction && p.Actions[0].ActionID != slackDenyAction) {
		w.WriteHeader(http.StatusOK)
		return
	}
	msg := h.slackDecide(r, ch, cfg, p.User.ID, p.Actions[0].Value, p.Actions[0].ActionID == slackApproveAction)
	go func() {
		if err := alerts.SlackRespond(p.ResponseURL, msg); err != nil {
			log.Err(err).Msg("santa: error answering Slack")
		}
	}()
	w.WriteHeader(http.StatusOK)
}

// slackDecide decides the request a button names, as the osctrl user the
// Slack user matches, and returns the message for Slack: the updated
// notification, or a note only the clicking user sees.
func (h *HandlersApi) slackDecide(r *http.Request, ch alerts.AlertChannel, cfg alerts.SlackConfig, slackUser, value string, approve bool) map[string]any {
	refuse := func(text string) map[string]any {
		return map[string]any{"response_type": "ephemeral", "replace_original": false, "text": text}
	}
	envUUID, token, _ := strings.Cut(value, ":")
	env, err := h.Envs.GetByUUID(envUUID)
	if err != nil || (ch.EnvironmentID != alerts.NoEnvironmentID && ch.EnvironmentID != env.ID) {
		return refuse("This request is not available.")
	}
	envCfg, err := h.Santa.Config(env.ID)
	if err != nil || !slices.Contains(envCfg.NotifyChannels, ch.ID) {
		return refuse("This request is not available.")
	}
	email, err := alerts.SlackUserEmail(cfg.Token, slackUser)
	if err != nil {
		log.Err(err).Str("slack_user", slackUser).Msg("santa: error reading Slack user email")
		return refuse("osctrl could not read the confirmed email of your Slack account.")
	}
	names, err := h.Santa.UsersByEmail(email)
	if err != nil || len(names) != 1 {
		return refuse("Your Slack email does not match exactly one osctrl user.")
	}
	user := names[0]
	if u, err := h.Users.Get(user); err != nil || u.Service {
		return refuse("Your Slack email does not match exactly one osctrl user.")
	}
	admin := h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, env.UUID)
	if !admin {
		if ok, err := h.Santa.IsApprover(envCfg, user); err != nil || !ok {
			h.santaAudit(user, "decision via Slack refused: not an admin or approver", r, env)
			return refuse("You are not an environment admin or approver in osctrl.")
		}
	}
	d := santa.Decision{Approve: approve, By: user, NotOwn: !admin, Scope: "node"}
	if !approve {
		d.Scope, d.Reason = "", slackDenyReason
	}
	req, err := h.Santa.DecideByLink(env.ID, token, d)
	if code, msg := santaDecisionError(err); code != 0 {
		if errors.Is(err, santa.ErrRiskFlagged) {
			msg = "A risk check flagged this file; use the approve link to override it with a reason."
		}
		return refuse(msg)
	}
	h.santaDecisionDone(r, env, d, " via Slack", req)
	verdict := "Denied"
	if req.Status == santa.RequestApproved {
		verdict = "Approved for this machine"
	}
	return map[string]any{
		"replace_original": true,
		"text":             alerts.SlackEscape(santa.RequestNotice(req)) + "\n" + verdict + " by " + alerts.SlackEscape(user) + " in Slack.",
	}
}
