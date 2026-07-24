package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"gorm.io/gorm"
)

type consoleCommandRequest struct {
	Input       string `json:"input"`
	OsqueryMode bool   `json:"osquery_mode"`
}

type consoleCommandResponse struct {
	Command console.Command       `json:"command"`
	Parsed  console.ParsedCommand `json:"parsed"`
}

type consoleNodeInfo struct {
	IPAddress       string `json:"ip_address"`
	OsqueryUser     string `json:"osquery_user"`
	OsqueryVersion  string `json:"osquery_version"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
}

type consoleSessionResponse struct {
	Session  console.Session        `json:"session"`
	History  []console.HistoryEntry `json:"history"`
	NodeInfo consoleNodeInfo        `json:"node_info"`
}

const defaultConsoleQueryReadSeconds = 5

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
	history, err := h.Console.History(env.ID, node.ID, ctx[ctxUser], 100)
	if err != nil {
		apiErrorResponse(w, "error getting console history", http.StatusInternalServerError, err)
		return
	}
	session, err := h.Console.CreateSession(env, node, ctx[ctxUser])
	if err != nil {
		apiErrorResponse(w, "error creating console session", http.StatusInternalServerError, err)
		return
	}
	h.auditConsoleVisit(ctx[ctxUser], r, env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, consoleSessionResponse{
		Session:  session,
		History:  history,
		NodeInfo: consoleNodeInfoFromNode(node),
	})
}

func (h *HandlersApi) ConsoleSessionShowHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, session, ok := h.consoleSessionContext(w, r)
	if !ok {
		return
	}
	session, err := h.Console.TouchSession(session.ID)
	if err != nil {
		apiErrorResponse(w, "error refreshing console session", http.StatusInternalServerError, err)
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
	preview, err := console.ParseInput(body.Input, session.CWD, session.Platform, body.OsqueryMode)
	if err != nil {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	if preview.Kind == console.CommandCarve && !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use console get by user %s", ctx[ctxUser]))
		return
	}

	command, parsed, err := h.Console.SubmitCommandWithTimeout(session.ID, body.Input, h.consoleCommandTimeout(preview), body.OsqueryMode)
	if err != nil {
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
		return
	}
	if parsed.Kind == console.CommandCarve {
		carveName, err := h.createConsoleCarve(env, session, ctx[ctxUser], parsed.Path)
		if err != nil {
			apiErrorResponse(w, "error creating carve", http.StatusInternalServerError, err)
			return
		}
		parsed.Message = "created carve " + carveName
	} else if parsed.Kind == console.CommandLocal && parsed.Command == "tables" && parsed.Mode == "osquery" {
		parsed.Output = h.consoleTablesOutput(session.Platform)
	}
	if h.AuditLog != nil {
		h.AuditLog.QueryAction(ctx[ctxUser], "console command "+parsed.Command, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, consoleCommandResponse{Command: command, Parsed: parsed})
}

func (h *HandlersApi) createConsoleCarve(env environments.TLSEnvironment, session console.Session, creator, path string) (string, error) {
	newQuery := queries.DistributedQuery{
		Query:         carves.GenCarveQuery(path, false),
		Name:          carves.GenCarveName(),
		Creator:       "console:" + creator,
		Active:        true,
		Type:          queries.CarveQueryType,
		Path:          path,
		EnvironmentID: env.ID,
		Expected:      1,
	}
	if err := h.Queries.Create(&newQuery); err != nil {
		return "", err
	}
	if err := h.Queries.CreateNodeQueries([]uint{session.NodeID}, newQuery.ID); err != nil {
		return "", err
	}
	if err := h.Queries.CreateTarget(newQuery.Name, "uuid", session.NodeUUID); err != nil {
		return "", err
	}
	if err := h.Queries.SetExpected(newQuery.Name, 1, env.ID); err != nil {
		return "", err
	}
	if h.AuditLog != nil {
		h.AuditLog.NewCarve(creator, path, "", env.ID)
	}
	return newQuery.Name, nil
}

func consoleNodeInfoFromNode(node nodes.OsqueryNode) consoleNodeInfo {
	return consoleNodeInfo{
		IPAddress:       node.IPAddress,
		OsqueryUser:     node.OsqueryUser,
		OsqueryVersion:  node.OsqueryVersion,
		Platform:        node.Platform,
		PlatformVersion: node.PlatformVersion,
	}
}

func (h *HandlersApi) consoleTablesOutput(platform string) string {
	names := make([]string, 0, len(h.OsqueryTables))
	for _, table := range h.OsqueryTables {
		if osqueryTableSupportsPlatform(table, platform) {
			names = append(names, table.Name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		if platform == "" {
			return "no osquery tables loaded"
		}
		return "no osquery tables loaded for " + platform
	}
	label := platform
	if label == "" {
		label = "all platforms"
	}
	return fmt.Sprintf("tables for %s (%d)\n%s", label, len(names), strings.Join(names, "\n"))
}

func (h *HandlersApi) consoleCommandTimeout(parsed console.ParsedCommand) time.Duration {
	seconds := int64(defaultConsoleQueryReadSeconds)
	if h.Settings != nil {
		if configured, err := h.Settings.GetInteger(config.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironmentID); err == nil && configured > 0 {
			seconds = configured
		}
	}
	if parsed.Kind == console.CommandRemote && parsed.Command == "sql" {
		timeout := time.Duration(seconds*12) * time.Second
		if timeout < time.Minute {
			return time.Minute
		}
		return timeout
	}
	return time.Duration(seconds*2) * time.Second
}

func osqueryTableSupportsPlatform(table types.OsqueryTable, platform string) bool {
	if platform == "" {
		return true
	}
	if len(table.Platforms) == 0 {
		return true
	}
	nodeBucket := nodes.NormalizePlatformBucket(platform)
	for _, supported := range table.Platforms {
		if strings.EqualFold(supported, platform) || nodes.NormalizePlatformBucket(supported) == nodeBucket {
			return true
		}
	}
	return false
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
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
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
