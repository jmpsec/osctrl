package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

type consoleCommandRequest struct {
	Input string `json:"input"`
}

type consoleCommandResponse struct {
	Command console.Command       `json:"command"`
	Parsed  console.ParsedCommand `json:"parsed"`
}

func (h *HandlersApi) ConsoleSessionCreateHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.consoleEnvContext(w, r)
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
	session, err := h.Console.CreateSession(env, node, ctx[ctxUser])
	if err != nil {
		apiErrorResponse(w, "error creating console session", http.StatusInternalServerError, err)
		return
	}
	h.auditConsoleVisit(ctx[ctxUser], r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, session)
}

func (h *HandlersApi) ConsoleSessionShowHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	h.auditConsoleVisit(ctx[ctxUser], r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, session)
}

func (h *HandlersApi) ConsoleSessionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	if err := h.Console.CloseSession(session.ID); err != nil {
		apiErrorResponse(w, "error closing console session", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "console session closed"})
}

func (h *HandlersApi) ConsoleCommandCreateHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	var body consoleCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	command, parsed, err := h.Console.SubmitCommand(session.ID, body.Input)
	if err != nil {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	if h.AuditLog != nil {
		h.AuditLog.QueryAction(ctx[ctxUser], "console command "+parsed.Command, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, consoleCommandResponse{Command: command, Parsed: parsed})
}

func (h *HandlersApi) ConsoleCommandShowHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	commandID, ok := consolePathUint(w, r, "command_id")
	if !ok {
		return
	}
	command, err := h.Console.GetCommand(session.ID, commandID)
	if err != nil {
		consoleNotFoundOrError(w, "command not found", "error getting command", err)
		return
	}
	command, err = h.Console.RefreshCommandStatus(command.ID)
	if err != nil {
		apiErrorResponse(w, "error refreshing command", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, command)
}

func (h *HandlersApi) ConsoleCommandResultsHandler(w http.ResponseWriter, r *http.Request) {
	_, _, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	commandID, ok := consolePathUint(w, r, "command_id")
	if !ok {
		return
	}
	command, err := h.Console.GetCommand(session.ID, commandID)
	if err != nil {
		consoleNotFoundOrError(w, "command not found", "error getting command", err)
		return
	}
	results, err := h.Console.CommandResults(command.ID)
	if err != nil {
		apiErrorResponse(w, "error getting command results", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, results)
}

func (h *HandlersApi) consoleEnvContext(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, ContextValue, bool) {
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing env", http.StatusBadRequest, nil)
		return environments.TLSEnvironment{}, nil, false
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
			return environments.TLSEnvironment{}, nil, false
		}
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		return environments.TLSEnvironment{}, nil, false
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return environments.TLSEnvironment{}, nil, false
	}
	return env, ctx, true
}

func (h *HandlersApi) consoleSessionContext(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, ContextValue, console.Session, bool) {
	env, ctx, ok := h.consoleEnvContext(w, r)
	if !ok {
		return environments.TLSEnvironment{}, nil, console.Session{}, false
	}
	sessionID, ok := consolePathUint(w, r, "session_id")
	if !ok {
		return environments.TLSEnvironment{}, nil, console.Session{}, false
	}
	session, err := h.Console.GetSession(sessionID)
	if err != nil {
		consoleNotFoundOrError(w, "session not found", "error getting session", err)
		return environments.TLSEnvironment{}, nil, console.Session{}, false
	}
	if session.EnvironmentID != env.ID {
		apiErrorResponse(w, "session not found", http.StatusNotFound, nil)
		return environments.TLSEnvironment{}, nil, console.Session{}, false
	}
	if session.Creator != ctx[ctxUser] {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use console session by user %s", ctx[ctxUser]))
		return environments.TLSEnvironment{}, nil, console.Session{}, false
	}
	return env, ctx, session, true
}

func consolePathUint(w http.ResponseWriter, r *http.Request, name string) (uint, bool) {
	value := r.PathValue(name)
	id, err := strconv.ParseUint(value, 10, strconv.IntSize)
	if value == "" || err != nil {
		apiErrorResponse(w, "invalid "+name, http.StatusBadRequest, err)
		return 0, false
	}
	return uint(id), true
}

func consoleNotFoundOrError(w http.ResponseWriter, notFoundMsg, errorMsg string, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, notFoundMsg, http.StatusNotFound, err)
		return
	}
	apiErrorResponse(w, errorMsg, http.StatusInternalServerError, err)
}

func (h *HandlersApi) auditConsoleVisit(user string, r *http.Request, envID uint) {
	if h.AuditLog != nil {
		h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], envID)
	}
}
