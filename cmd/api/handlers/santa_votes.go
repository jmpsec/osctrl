package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// SantaVoteCreate is a vote to allow a blocked file.
type SantaVoteCreate struct {
	// SHA-256 of the blocked file, from the block dialog link
	SHA256 string `json:"sha256"`
	// Machine (node) UUID, from the block dialog link
	MachineID string `json:"machine_id"`
}

// SantaVoteHandler — POST /api/v1/santa/{env}/votes
// @Summary Vote to allow a binary Santa blocked
// @Description Any signed-in account may call this; no environment permission is needed. The block must have been reported by the machine. One vote per account and file: voting again changes nothing. At the local threshold each voter's machine gets a BINARY allow rule; at the global threshold the environment gets one. A file blocked by a rule cannot be voted for (409), and neither can any file while both thresholds are 0 (409).
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaVoteCreate true "Vote"
// @Success 200 {object} santa.VoteStatus
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/votes [post]
func (h *HandlersApi) SantaVoteHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaRequester(w, r)
	if !ok {
		return
	}
	var body SantaVoteCreate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&body); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	res, err := h.Santa.Vote(env.ID, body.MachineID, body.SHA256, user)
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case errors.Is(err, santa.ErrNoBlockedEvent):
		apiErrorResponse(w, santaRequestNotFound, http.StatusNotFound, err)
		return
	case errors.Is(err, santa.ErrVotingOff):
		apiErrorResponse(w, "voting is off", http.StatusConflict, err)
		return
	case errors.Is(err, santa.ErrRiskFlagged):
		apiErrorResponse(w, "a risk check flagged this file; it cannot be voted for", http.StatusConflict, err)
		return
	case errors.Is(err, santa.ErrRiskUnavailable):
		apiErrorResponse(w, err.Error(), http.StatusServiceUnavailable, err)
		return
	case errors.Is(err, santa.ErrKnownBad), errors.Is(err, santa.ErrRuleConflict):
		apiErrorResponse(w, "this file is blocked by a rule and cannot be voted for", http.StatusConflict, err)
		return
	case err != nil:
		apiErrorResponse(w, "error voting", http.StatusInternalServerError, err)
		return
	}
	if res.Counted {
		// Validated by Vote, give or take surrounding space.
		h.santaAudit(user, fmt.Sprintf("vote sha256=%s machine=%s votes=%d",
			strings.TrimSpace(body.SHA256), strings.TrimSpace(body.MachineID), res.Votes), r, env)
	}
	for _, rule := range res.Rules {
		h.santaAudit(user, fmt.Sprintf("votes created rule=%d sha256=%s scope=%s%s votes=%d",
			rule.ID, rule.Identifier, rule.Scope, scopeValueSuffix(rule.ScopeValue), res.Votes), r, env)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, res.VoteStatus)
}

// SantaVoteStatusHandler — GET /api/v1/santa/{env}/votes
// @Summary Get the votes for a binary
// @Description Any signed-in account may call this. Returns the vote count, both thresholds (0 is off) and whether the caller voted; never who voted.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param sha256 query string true "SHA-256 of the file"
// @Success 200 {object} santa.VoteStatus
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/votes [get]
func (h *HandlersApi) SantaVoteStatusHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaRequester(w, r)
	if !ok {
		return
	}
	st, err := h.Santa.VoteStatus(env.ID, r.URL.Query().Get("sha256"), user)
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error getting votes", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, st)
}
