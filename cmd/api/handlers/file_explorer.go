package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

type fileExplorerPathRequest struct {
	Path string `json:"path"`
}

type fileExplorerSessionResponse struct {
	Session  fileexplorer.Session `json:"session"`
	NodeInfo consoleNodeInfo      `json:"node_info"`
	// Priming is the priming metadata request dispatched at session
	// creation. The frontend polls the new priming results endpoint with
	// this request id to render live osquery_info metadata, and its
	// presence in the node's pending queue warms acceleration. May be nil
	// if priming submission failed.
	Priming *fileexplorer.Request `json:"priming,omitempty"`
}

func (h *HandlersApi) FileExplorerSessionCreateHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.fileExplorerEnvContext(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		apiErrorResponse(w, "missing node uuid", http.StatusBadRequest, nil)
		return
	}
	node, err := h.Nodes.GetByUUIDEnv(uuid, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "node not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting node", http.StatusInternalServerError, err)
		return
	}
	session, err := h.FileExplorer.CreateSession(env, node, ctx[ctxUser])
	if err != nil {
		apiErrorResponse(w, "error creating file explorer session", http.StatusInternalServerError, err)
		return
	}
	// Dispatch a priming metadata query so live osquery_info metadata can
	// be surfaced in the file explorer header. When acceleration is
	// enabled, the node's next QueryRead can also switch to fast polling
	// before the operator expands the first directory. Non-fatal on
	// failure.
	var priming *fileexplorer.Request
	if primingReq, primingErr := h.FileExplorer.SubmitPrimingRequest(session.ID, h.fileExplorerRequestTimeout()); primingErr == nil {
		priming = &primingReq
	}
	h.auditFileExplorerAction(ctx[ctxUser], "file explorer session", r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, fileExplorerSessionResponse{
		Session:  session,
		NodeInfo: consoleNodeInfoFromNode(node),
		Priming:  priming,
	})
}

func (h *HandlersApi) FileExplorerSessionShowHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	session, err := h.FileExplorer.TouchSession(session.ID)
	if err != nil {
		apiErrorResponse(w, "error refreshing file explorer session", http.StatusInternalServerError, err)
		return
	}
	h.auditFileExplorerAction(ctx[ctxUser], "file explorer session", r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, session)
}

func (h *HandlersApi) FileExplorerSessionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	if err := h.FileExplorer.CloseSession(session.ID); err != nil {
		apiErrorResponse(w, "error closing file explorer session", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "file explorer session closed"})
}

func (h *HandlersApi) FileExplorerListHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	path, ok := fileExplorerRequestPath(w, r)
	if !ok {
		return
	}
	request, err := h.FileExplorer.ListDirectory(session.ID, path, h.fileExplorerRequestTimeout())
	if err != nil {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	h.auditFileExplorerAction(ctx[ctxUser], "file explorer list", r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, request)
}

func (h *HandlersApi) FileExplorerStatHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	path, ok := fileExplorerRequestPath(w, r)
	if !ok {
		return
	}
	request, err := h.FileExplorer.StatPath(session.ID, path, h.fileExplorerRequestTimeout())
	if err != nil {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	h.auditFileExplorerAction(ctx[ctxUser], "file explorer stat", r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, request)
}

func (h *HandlersApi) FileExplorerRequestShowHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	requestID, ok := consolePathUint(w, r, "request_id")
	if !ok {
		return
	}
	request, err := h.FileExplorer.GetRequest(session.ID, requestID)
	if err != nil {
		consoleNotFoundOrError(w, "request not found", "error getting file explorer request", err)
		return
	}
	request, err = h.FileExplorer.RefreshRequestStatus(request.ID)
	if err != nil {
		apiErrorResponse(w, "error refreshing file explorer request", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, request)
}

func (h *HandlersApi) FileExplorerRequestResultsHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	requestID, ok := consolePathUint(w, r, "request_id")
	if !ok {
		return
	}
	request, err := h.FileExplorer.GetRequest(session.ID, requestID)
	if err != nil {
		consoleNotFoundOrError(w, "request not found", "error getting file explorer request", err)
		return
	}
	results, err := h.FileExplorer.RequestResults(request.ID)
	if err != nil {
		apiErrorResponse(w, "error getting file explorer results", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, results)
}

// FileExplorerPrimingResultsHandler returns the raw osquery_info rows
// for the session's priming metadata request. Unlike the list/stat
// results endpoint (which decodes file columns into Entry structs), this
// returns the generic row maps so the frontend can render osquery_info
// columns directly.
func (h *HandlersApi) FileExplorerPrimingResultsHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.fileExplorerSessionContext(w, r)
	if !ok {
		return
	}
	requestID, ok := consolePathUint(w, r, "request_id")
	if !ok {
		return
	}
	request, err := h.FileExplorer.GetRequest(session.ID, requestID)
	if err != nil {
		consoleNotFoundOrError(w, "request not found", "error getting file explorer request", err)
		return
	}
	rows, err := h.FileExplorer.RequestMetadataRows(request.ID)
	if err != nil {
		apiErrorResponse(w, "error getting file explorer metadata", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rows)
}

func (h *HandlersApi) fileExplorerEnvContext(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, ContextValue, bool) {
	if h.FileExplorer == nil {
		apiErrorResponse(w, "file explorer unavailable", http.StatusNotFound, nil)
		return environments.TLSEnvironment{}, nil, false
	}
	return h.consoleEnvContext(w, r)
}

func (h *HandlersApi) fileExplorerSessionContext(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, ContextValue, fileexplorer.Session, bool) {
	env, ctx, ok := h.fileExplorerEnvContext(w, r)
	if !ok {
		return environments.TLSEnvironment{}, nil, fileexplorer.Session{}, false
	}
	sessionID, ok := consolePathUint(w, r, "session_id")
	if !ok {
		return environments.TLSEnvironment{}, nil, fileexplorer.Session{}, false
	}
	session, err := h.FileExplorer.GetSession(sessionID)
	if err != nil {
		consoleNotFoundOrError(w, "session not found", "error getting file explorer session", err)
		return environments.TLSEnvironment{}, nil, fileexplorer.Session{}, false
	}
	if session.EnvironmentID != env.ID {
		apiErrorResponse(w, "session not found", http.StatusNotFound, nil)
		return environments.TLSEnvironment{}, nil, fileexplorer.Session{}, false
	}
	if session.Creator != ctx[ctxUser] {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use file explorer session by user %s", ctx[ctxUser]))
		return environments.TLSEnvironment{}, nil, fileexplorer.Session{}, false
	}
	return env, ctx, session, true
}

func fileExplorerRequestPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	var body fileExplorerPathRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return "", false
	}
	return body.Path, true
}

func (h *HandlersApi) fileExplorerRequestTimeout() time.Duration {
	seconds := int64(defaultConsoleQueryReadSeconds)
	if h.Settings != nil {
		if configured, err := h.Settings.GetInteger(config.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironmentID); err == nil && configured > 0 {
			seconds = configured
		}
	}
	return time.Duration(seconds*2) * time.Second
}

func (h *HandlersApi) auditFileExplorerAction(user, action string, r *http.Request, envID uint) {
	if h.AuditLog != nil {
		h.AuditLog.QueryAction(user, action, strings.Split(r.RemoteAddr, ":")[0], envID)
	}
}
