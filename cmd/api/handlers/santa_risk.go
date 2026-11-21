package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// santaWarmRisk runs the risk checks for a new request in the background, so
// approvers see a verdict in the queue. A failure is cached and shown there.
func (h *HandlersApi) santaWarmRisk(envID uint, sha256 string) {
	if h.Santa == nil {
		return
	}
	// ponytail: one goroutine per new request, bounded by the per-requester
	// pending cap like the notification; queue it if volume ever matters.
	go func() {
		if _, err := h.Santa.CheckRisk(context.Background(), envID, sha256); err != nil {
			log.Err(err).Msg("santa: risk check failed")
		}
	}()
}

// SantaBinaryRiskHandler — POST /api/v1/santa/{env}/binaries/{sha256}/risk
// @Summary Run the Santa risk checks for a binary
// @Description Requires environment admin. Runs every risk check of the environment whose cached verdict is missing or expired (VirusTotal, custom webhook) and returns the result. Only the hash is sent. 404 when the environment runs no risk check.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param sha256 path string true "SHA-256 of the file"
// @Success 200 {object} santa.Risk
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/binaries/{sha256}/risk [post]
func (h *HandlersApi) SantaBinaryRiskHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	risk, err := h.Santa.CheckRisk(r.Context(), env.ID, r.PathValue("sha256"))
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error running risk checks", http.StatusInternalServerError, err)
		return
	case risk == nil:
		apiErrorResponse(w, "no risk check is configured for this environment", http.StatusNotFound, nil)
		return
	}
	h.santaAudit(user, "risk check sha256="+r.PathValue("sha256")+" verdict="+risk.Verdict, r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, risk)
}

// SantaRiskOverrideRequest lets votes go ahead despite a risk verdict.
type SantaRiskOverrideRequest struct {
	// Why votes may allow this file, at most 1000 characters
	Reason string `json:"reason"`
}

// SantaRiskOverrideHandler — PUT /api/v1/santa/{env}/binaries/{sha256}/risk-override
// @Summary Let votes allow a file despite its risk verdict
// @Description Requires environment admin. Votes for the file skip the risk checks in this environment; the verdict itself is unchanged, and approvals keep their own per-decision override. Audited, and held for a second admin when the environment requires one. Replaces an existing override.
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param sha256 path string true "SHA-256 of the file"
// @Param body body SantaRiskOverrideRequest true "Reason"
// @Success 200 {object} santa.RiskOverride
// @Success 202 {object} PendingChangeResponse "Held for a second admin (require_second_admin)"
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/binaries/{sha256}/risk-override [put]
func (h *HandlersApi) SantaRiskOverrideHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	var req SantaRiskOverrideRequest
	body, err := readJSONBody(w, r, santaMaxBody, &req)
	if err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	sha := strings.ToLower(r.PathValue("sha256"))
	if h.santaHeld(w, r, env, user, "risk override for votes sha256="+sha, body) {
		return
	}
	o, err := h.Santa.SetRiskOverride(env.ID, sha, user, req.Reason)
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error saving risk override", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "risk override for votes sha256="+sha+" reason="+oneLineAudit(o.Reason), r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, o)
}

// SantaRiskOverrideDeleteHandler — DELETE /api/v1/santa/{env}/binaries/{sha256}/risk-override
// @Summary Remove the voting override of a file's risk verdict
// @Description Requires environment admin. Votes for the file run the risk checks again. Audited.
// @Tags santa
// @Param env path string true "Environment name or UUID"
// @Param sha256 path string true "SHA-256 of the file"
// @Success 204
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/binaries/{sha256}/risk-override [delete]
func (h *HandlersApi) SantaRiskOverrideDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	sha := strings.ToLower(r.PathValue("sha256"))
	found, err := h.Santa.DeleteRiskOverride(env.ID, sha)
	if err != nil {
		apiErrorResponse(w, "error removing risk override", http.StatusInternalServerError, err)
		return
	}
	if !found {
		apiErrorResponse(w, "no risk override for this file", http.StatusNotFound, nil)
		return
	}
	h.santaAudit(user, "remove risk override for votes sha256="+sha, r, env)
	w.WriteHeader(http.StatusNoContent)
}

// oneLineAudit keeps a user-written value on one audit line, at most 200 characters.
func oneLineAudit(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
