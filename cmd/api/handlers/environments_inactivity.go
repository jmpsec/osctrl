package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

type InactiveHoursRequest struct {
	InactiveHours *int64 `json:"inactive_hours" binding:"required" minimum:"1" maximum:"2562047"`
}

// EnvironmentInactiveHoursHandler returns the effective node inactivity policy.
// @Summary Get environment inactivity threshold
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} settings.InactivityPolicy
// @Failure 401 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 500 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/environments/inactive-hours/{env} [get]
func (h *HandlersApi) EnvironmentInactiveHoursHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.inactivityEnvironment(w, r, users.UserLevel)
	if !ok {
		return
	}
	policy, err := h.Settings.InactivityPolicy(env.ID)
	if err != nil {
		apiErrorResponse(w, "error reading inactivity threshold", http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, policy)
}

// EnvironmentInactiveHoursSetHandler saves an environment override.
// @Summary Set environment inactivity threshold
// @Tags environments
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body InactiveHoursRequest true "Positive whole hours (1 to 2562047)"
// @Success 200 {object} settings.InactivityPolicy
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 401 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 500 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/environments/inactive-hours/{env} [put]
func (h *HandlersApi) EnvironmentInactiveHoursSetHandler(w http.ResponseWriter, r *http.Request) {
	h.changeEnvironmentInactiveHours(w, r)
}

// EnvironmentInactiveHoursResetHandler restores global inheritance.
// @Summary Reset environment inactivity threshold
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} settings.InactivityPolicy
// @Failure 401 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 500 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/environments/inactive-hours/{env} [delete]
func (h *HandlersApi) EnvironmentInactiveHoursResetHandler(w http.ResponseWriter, r *http.Request) {
	h.changeEnvironmentInactiveHours(w, r)
}

func (h *HandlersApi) inactivityEnvironment(w http.ResponseWriter, r *http.Request, level users.AccessLevel) (environments.TLSEnvironment, ContextValue, bool) {
	ctx, ok := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !ok {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return environments.TLSEnvironment{}, nil, false
	}
	env, err := h.Envs.Get(r.PathValue("env"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusNotFound
		}
		apiErrorResponse(w, "error getting environment", status, err)
		return env, ctx, false
	}
	if !h.Users.CheckPermissions(ctx[ctxUser], level, env.UUID) {
		h.denyEnv(w, r, ctx, env.ID, "permission check failed")
		return env, ctx, false
	}
	return env, ctx, true
}

func (h *HandlersApi) changeEnvironmentInactiveHours(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return
	}
	var body InactiveHoursRequest
	if r.Method == http.MethodPut {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			apiErrorResponse(w, "invalid inactivity threshold", http.StatusBadRequest, err)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF || body.InactiveHours == nil {
			apiErrorResponse(w, "provide one inactive_hours integer", http.StatusBadRequest, err)
			return
		}
		if err := settings.ValidateInactiveHours(*body.InactiveHours); err != nil {
			apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
			return
		}
	}
	before, after, err := h.Envs.SetInactiveHours(env.ID, body.InactiveHours)
	if err != nil {
		apiErrorResponse(w, "error updating inactivity threshold", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], fmt.Sprintf("inactive_hours: %d (%s) -> %d (%s)", before.InactiveHours, before.Source, after.InactiveHours, after.Source), utils.GetIP(r), env.ID)
	w.Header().Set("Cache-Control", "no-store")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, after)
}
