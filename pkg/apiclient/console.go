package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/console"
)

// Console session + command API wrappers. These mirror the /console routes:
//   POST   /api/v1/console/{env}/nodes/{uuid}/sessions
//   GET    /api/v1/console/{env}/sessions/{session_id}
//   DELETE /api/v1/console/{env}/sessions/{session_id}
//   POST   /api/v1/console/{env}/sessions/{session_id}/commands
//   GET    /api/v1/console/{env}/sessions/{session_id}/commands/{command_id}
//   GET    /api/v1/console/{env}/sessions/{session_id}/commands/{command_id}/results

// ConsoleNodeInfo mirrors the API's node_info projection for a console session.
type ConsoleNodeInfo struct {
	IPAddress       string `json:"ip_address"`
	OsqueryUser     string `json:"osquery_user"`
	OsqueryVersion  string `json:"osquery_version"`
	Platform        string `json:"platform"`
	PlatformVersion string `json:"platform_version"`
}

// ConsoleSessionResponse mirrors the create-session response (session + history + node info).
type ConsoleSessionResponse struct {
	Session  console.Session        `json:"session"`
	History  []console.HistoryEntry `json:"history"`
	NodeInfo ConsoleNodeInfo        `json:"node_info"`
}

// ConsoleCommandResponse mirrors the submit-command response.
type ConsoleCommandResponse struct {
	Command console.Command       `json:"command"`
	Parsed  console.ParsedCommand `json:"parsed"`
}

// CreateConsoleSession opens a console session against a node.
func (api *OsctrlAPI) CreateConsoleSession(env, uuid string) (ConsoleSessionResponse, error) {
	var res ConsoleSessionResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/console", env, "nodes", uuid, "sessions"))
	raw, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}

// CloseConsoleSession closes a console session.
func (api *OsctrlAPI) CloseConsoleSession(env string, sessionID uint) error {
	var r struct {
		Message string `json:"message"`
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/console", env, "sessions", strconv.FormatUint(uint64(sessionID), 10)))
	raw, err := api.ReqGeneric("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// GetConsoleSession retrieves the current state of a console session.
func (api *OsctrlAPI) GetConsoleSession(env string, sessionID uint) (console.Session, error) {
	var session console.Session
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/console", env, "sessions", strconv.FormatUint(uint64(sessionID), 10)))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return session, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &session); err != nil {
		return session, fmt.Errorf("can not parse body - %w", err)
	}
	return session, nil
}

// SubmitConsoleCommand sends a console command within a session.
func (api *OsctrlAPI) SubmitConsoleCommand(env string, sessionID uint, input string, osqueryMode bool) (ConsoleCommandResponse, error) {
	var res ConsoleCommandResponse
	body := struct {
		Input       string `json:"input"`
		OsqueryMode bool   `json:"osquery_mode"`
	}{Input: input, OsqueryMode: osqueryMode}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return res, fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/console", env, "sessions", strconv.FormatUint(uint64(sessionID), 10), "commands"))
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}

// GetConsoleCommand retrieves the current state of a console command.
func (api *OsctrlAPI) GetConsoleCommand(env string, sessionID, commandID uint) (console.Command, error) {
	var cmd console.Command
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/console", env, "sessions", strconv.FormatUint(uint64(sessionID), 10),
			"commands", strconv.FormatUint(uint64(commandID), 10)))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return cmd, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return cmd, fmt.Errorf("can not parse body - %w", err)
	}
	return cmd, nil
}

// GetConsoleCommandResults retrieves the rows produced by a completed console command.
func (api *OsctrlAPI) GetConsoleCommandResults(env string, sessionID, commandID uint) ([]map[string]any, error) {
	var rows []map[string]any
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/console", env, "sessions", strconv.FormatUint(uint64(sessionID), 10),
			"commands", strconv.FormatUint(uint64(commandID), 10), "results"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return rows, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return rows, fmt.Errorf("can not parse body - %w", err)
	}
	return rows, nil
}
