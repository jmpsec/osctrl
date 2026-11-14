package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// SantaRequestCreate is what a blocked user submits.
type SantaRequestCreate struct {
	// SHA-256 of the blocked file, from the block dialog link
	SHA256 string `json:"sha256"`
	// Machine (node) UUID, from the block dialog link
	MachineID string `json:"machine_id"`
	// Why the software is needed; at most 1000 characters
	Justification string `json:"justification"`
}

// SantaOwnRequest is the requester's view of a request. It carries nothing
// about the machine, the event or other users.
type SantaOwnRequest struct {
	ID         uint      `json:"id"`
	FileSHA256 string    `json:"file_sha256"`
	MachineID  string    `json:"machine_id"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	// Empty when the request was made by someone else
	Justification string `json:"justification"`
}

func ownRequest(r santa.Request, user string) SantaOwnRequest {
	out := SantaOwnRequest{ID: r.ID, FileSHA256: r.FileSHA256, MachineID: r.MachineID, Status: r.Status, CreatedAt: r.CreatedAt}
	if r.Requester == user {
		out.Justification = r.Justification
	}
	return out
}

// santaRequestNotFound is the one answer for an unknown environment, an
// environment without approval requests and a block osctrl has not seen, so
// the route is not an oracle for any of them.
const santaRequestNotFound = "no blocked execution found for this file and machine; Santa may not have reported it yet, try again in a minute"

// santaRequester resolves {env} for a signed-in caller without any environment
// permission: requesters are accounts that can do nothing else. It only passes
// environments that have approval requests turned on.
func (h *HandlersApi) santaRequester(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, string, bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return environments.TLSEnvironment{}, "", false
	}
	user := ctxVal.(ContextValue)[ctxUser]
	if h.Santa == nil {
		apiErrorResponse(w, "santa not enabled", http.StatusServiceUnavailable, nil)
		return environments.TLSEnvironment{}, "", false
	}
	env, err := h.Envs.Get(r.PathValue("env"))
	if err == nil {
		var cfg santa.EnvConfig
		if cfg, err = h.Santa.Config(env.ID); err == nil && cfg.ApprovalURL == "" {
			err = errors.New("approval requests are off")
		}
	}
	if err != nil {
		apiErrorResponse(w, santaRequestNotFound, http.StatusNotFound, err)
		return environments.TLSEnvironment{}, "", false
	}
	return env, user, true
}

// SantaRequestCreateHandler — POST /api/v1/santa/{env}/requests
// @Summary Request approval for a binary Santa blocked
// @Description Any signed-in account may call this; no environment permission is needed. The block must have been reported by the machine. A pending request for the same file and machine is returned (200) instead of creating a second one.
// @Tags santa
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param body body SantaRequestCreate true "Request"
// @Success 200 {object} SantaOwnRequest
// @Success 201 {object} SantaOwnRequest
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 429 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/requests [post]
func (h *HandlersApi) SantaRequestCreateHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaRequester(w, r)
	if !ok {
		return
	}
	var body SantaRequestCreate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, santaMaxBody)).Decode(&body); err != nil {
		apiErrorResponse(w, "invalid request", http.StatusBadRequest, err)
		return
	}
	req, created, err := h.Santa.CreateRequest(env.ID, body.MachineID, body.SHA256, user, body.Justification)
	switch {
	case errors.Is(err, santa.ErrInvalidRequest):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, nil)
		return
	case errors.Is(err, santa.ErrNoBlockedEvent):
		apiErrorResponse(w, santaRequestNotFound, http.StatusNotFound, err)
		return
	case errors.Is(err, santa.ErrTooManyRequests):
		apiErrorResponse(w, "too many pending requests", http.StatusTooManyRequests, err)
		return
	case err != nil:
		apiErrorResponse(w, "error creating request", http.StatusInternalServerError, err)
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
		h.santaAudit(user, "request approval sha256="+req.FileSHA256+" machine="+req.MachineID, r, env)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, code, ownRequest(req, user))
}

// SantaMyRequestsHandler — GET /api/v1/santa/{env}/requests/mine
// @Summary List the caller's own Santa approval requests
// @Description Any signed-in account may call this; it only returns requests the caller made.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} SantaOwnRequest
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/requests/mine [get]
func (h *HandlersApi) SantaMyRequestsHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaRequester(w, r)
	if !ok {
		return
	}
	reqs, err := h.Santa.Requests(env.ID, "", user)
	if err != nil {
		apiErrorResponse(w, "error listing requests", http.StatusInternalServerError, err)
		return
	}
	out := make([]SantaOwnRequest, 0, len(reqs))
	for _, q := range reqs {
		out = append(out, ownRequest(q, user))
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// SantaRequestsHandler — GET /api/v1/santa/{env}/requests
// @Summary List Santa approval requests
// @Description Newest first, at most 500. Requires environment admin.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param status query string false "pending, approved, denied or expired"
// @Success 200 {array} santa.Request
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/requests [get]
func (h *HandlersApi) SantaRequestsHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	reqs, err := h.Santa.Requests(env.ID, r.URL.Query().Get("status"), "")
	if err != nil {
		apiErrorResponse(w, "error listing requests", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, reqs)
}
