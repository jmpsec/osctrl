package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

// carveRecorder captures the response of the carve handler. net/http/httptest
// would do the same job, but it is a testing package and this runs in the server.
type carveRecorder struct {
	code   int
	header http.Header
	body   bytes.Buffer
}

func (c *carveRecorder) Header() http.Header         { return c.header }
func (c *carveRecorder) Write(b []byte) (int, error) { return c.body.Write(b) }
func (c *carveRecorder) WriteHeader(code int)        { c.code = code }

// SantaEventCarveHandler — POST /api/v1/santa/{env}/events/{id}/carve
// @Summary Retrieve the file of a Santa event from its machine
// @Description Requires environment admin. Starts an osquery file carve of the event's file on the machine that reported it, through the carves endpoint: the caller also needs carve access, sensitive paths stay refused, and the carve is stored and audited like any other. The carve name is recorded on the event. 409 when the event has no path or its machine is not an osquery node of the environment. The path is written by the Santa client.
// @Tags santa
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Event ID"
// @Success 201 {object} types.ApiQueriesResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Failure 409 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/santa/{env}/events/{id}/carve [post]
func (h *HandlersApi) SantaEventCarveHandler(w http.ResponseWriter, r *http.Request) {
	env, user, ok := h.santaEnvironment(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		apiErrorResponse(w, "invalid event id", http.StatusBadRequest, nil)
		return
	}
	ev, err := h.Santa.Event(env.ID, uint(id))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "event not found", http.StatusNotFound, nil)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error getting event", http.StatusInternalServerError, err)
		return
	}
	path := ev.FullPath()
	if path == "" {
		apiErrorResponse(w, "the event has no file path", http.StatusConflict, nil)
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(ev.MachineID, env.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "the machine is not an osquery node of this environment", http.StatusConflict, nil)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		return
	}
	// The carves handler owns carve authorization, sensitive paths, node scope,
	// storage and its audit line; dispatch to it rather than repeat any of that.
	body, err := json.Marshal(types.ApiDistributedQueryRequest{Path: path, UUIDs: []string{node.UUID}})
	if err != nil {
		apiErrorResponse(w, "error building carve", http.StatusInternalServerError, err)
		return
	}
	inner := r.Clone(r.Context())
	inner.Body = io.NopCloser(bytes.NewReader(body))
	inner.ContentLength = int64(len(body))
	inner.SetPathValue("env", env.UUID)
	rec := &carveRecorder{code: http.StatusOK, header: make(http.Header)}
	h.CarvesRunHandler(rec, inner)
	if rec.code != http.StatusCreated {
		for k, v := range rec.header {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.code)
		_, _ = w.Write(rec.body.Bytes())
		return
	}
	var created types.ApiQueriesResponse
	if err := json.Unmarshal(rec.body.Bytes(), &created); err != nil || created.Name == "" {
		apiErrorResponse(w, "error reading carve", http.StatusInternalServerError, err)
		return
	}
	if err := h.Santa.SetEventCarve(env.ID, ev.ID, created.Name); err != nil {
		apiErrorResponse(w, "carve started but not recorded on the event", http.StatusInternalServerError, err)
		return
	}
	h.santaAudit(user, "retrieve file event="+strconv.FormatUint(id, 10)+" carve="+created.Name, r, env)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, created)
}
