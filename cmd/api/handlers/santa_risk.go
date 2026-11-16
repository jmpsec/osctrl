package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// santaWarmRisk runs the risk checks for a new request in the background, so
// approvers see a verdict in the queue. A failure is cached and shown there.
func (h *HandlersApi) santaWarmRisk(sha256 string) {
	if h.Santa == nil || h.Santa.Risk == nil {
		return
	}
	// ponytail: one goroutine per new request, bounded by the per-requester
	// pending cap like the notification; queue it if volume ever matters.
	go func() {
		if _, err := h.Santa.CheckRisk(context.Background(), sha256); err != nil {
			log.Err(err).Msg("santa: risk check failed")
		}
	}()
}

// SantaBinaryRiskHandler — POST /api/v1/santa/{env}/binaries/{sha256}/risk
// @Summary Run the Santa risk checks for a binary
// @Description Requires environment admin. Runs every configured risk check whose cached verdict is missing or expired (VirusTotal, custom webhook) and returns the result. Only the hash is sent. 404 when no risk check is configured.
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
	if h.Santa.Risk == nil {
		apiErrorResponse(w, "no risk check is configured", http.StatusNotFound, nil)
		return
	}
	risk, err := h.Santa.CheckRisk(r.Context(), r.PathValue("sha256"))
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error running risk checks", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "risk check sha256="+r.PathValue("sha256")+" verdict="+risk.Verdict, r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, risk)
}
