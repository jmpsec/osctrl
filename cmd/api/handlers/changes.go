package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/changes"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

// PendingChangeResponse answers a held action with 202.
type PendingChangeResponse struct {
	Message       string         `json:"message"`
	PendingChange changes.Change `json:"pending_change"`
}

// ChangeView is a held change as listed; mine is true for the caller's own.
type ChangeView struct {
	changes.Change
	Mine bool `json:"mine"`
}

// ChangeDecision approves or denies a held change.
type ChangeDecision struct {
	// approve | deny; the requester can only deny (withdraw) their own change
	Decision string `json:"decision"`
}

// secondAdmin holds a risky action until another admin approves it. It returns
// true when the action may run now: an approval for this exact request (method,
// path and body) by this user was waiting and has been used. Otherwise it has
// answered 202 with the pending change, or an error.
func (h *HandlersApi) secondAdmin(w http.ResponseWriter, r *http.Request, env environments.TLSEnvironment, user, action string, body []byte) bool {
	if h.Changes == nil {
		apiErrorResponse(w, "change approval is not available", http.StatusServiceUnavailable, nil)
		return false
	}
	c, created, err := h.Changes.Gate(env.ID, user, action, r.Method, r.URL.Path, body)
	if err != nil {
		apiErrorResponse(w, "error holding change for approval", http.StatusInternalServerError, err)
		return false
	}
	if c.Status == changes.StatusApplied {
		h.AuditLog.EnvAction(user, fmt.Sprintf("change: apply %d %s approved_by=%s", c.ID, c.Action, c.DecidedBy), utils.GetIP(r), env.ID)
		return true
	}
	if created {
		h.AuditLog.EnvAction(user, fmt.Sprintf("change: request %d %s", c.ID, c.Action), utils.GetIP(r), env.ID)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, PendingChangeResponse{
		Message:       fmt.Sprintf("Change %d needs approval by another admin of this environment; apply it once approved", c.ID),
		PendingChange: c,
	})
	return false
}

// changesEnvironment resolves {env} and requires environment admin.
func (h *HandlersApi) changesEnvironment(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, string, bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return environments.TLSEnvironment{}, "", false
	}
	if h.Changes == nil {
		apiErrorResponse(w, "change approval is not available", http.StatusServiceUnavailable, nil)
		return environments.TLSEnvironment{}, "", false
	}
	user := ctxVal.(ContextValue)[ctxUser]
	env, err := h.Envs.Get(r.PathValue("env"))
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return environments.TLSEnvironment{}, "", false
	}
	if !h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return environments.TLSEnvironment{}, "", false
	}
	return env, user, true
}

// ChangesHandler — GET /api/v1/changes/{env}
// @Summary List changes held for a second admin
// @Description Newest first, at most 200. Requires environment admin.
// @Tags changes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} ChangeView
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/changes/{env} [get]
func (h *HandlersApi) ChangesHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.changesEnvironment(w, r)
	if !ok {
		return
	}
	cs, err := h.Changes.List(env.ID)
	if err != nil {
		apiErrorResponse(w, "error listing changes", http.StatusInternalServerError, err)
		return
	}
	out := make([]ChangeView, len(cs))
	for i, c := range cs {
		out[i] = ChangeView{Change: c, Mine: c.RequestedBy == user}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// ChangeDecideHandler — POST /api/v1/changes/{env}/{id}/decision
// @Summary Approve or deny a change held for a second admin
// @Description Requires environment admin. Only someone other than the requester can approve; the requester can deny to withdraw it. An approved change is applied by the requester sending the same request again within 24 hours of the request.
// @Tags changes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Change ID"
// @Param body body ChangeDecision true "Decision"
// @Success 200 {object} changes.Change
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/changes/{env}/{id}/decision [post]
func (h *HandlersApi) ChangeDecideHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.changesEnvironment(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "invalid change id", http.StatusBadRequest, err)
		return
	}
	var body ChangeDecision
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&body); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	if body.Decision != "approve" && body.Decision != "deny" {
		apiErrorResponse(w, "decision must be approve or deny", http.StatusBadRequest, nil)
		return
	}
	c, err := h.Changes.Decide(env.ID, uint(id), user, body.Decision == "approve")
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "change not found", http.StatusNotFound, err)
		return
	case errors.Is(err, changes.ErrSelfApproval):
		apiErrorResponse(w, "another admin must approve your own change", http.StatusForbidden, nil)
		return
	case errors.Is(err, changes.ErrNotPending):
		apiErrorResponse(w, "the change was already decided or has expired", http.StatusConflict, nil)
		return
	case err != nil:
		apiErrorResponse(w, "error deciding change", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.EnvAction(user, fmt.Sprintf("change: %s %d %s requester=%s", body.Decision, c.ID, c.Action, c.RequestedBy), utils.GetIP(r), env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, c)
}
