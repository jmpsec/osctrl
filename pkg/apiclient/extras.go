package apiclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// File explorer + posture + saved queries + node logs API wrappers.
//
// File explorer routes:
//   POST /api/v1/file-explorer/{env}/nodes/{uuid}/sessions
//   GET  /api/v1/file-explorer/{env}/sessions/{session_id}
//   DEL  /api/v1/file-explorer/{env}/sessions/{session_id}
//   POST /api/v1/file-explorer/{env}/sessions/{session_id}/list
//   POST /api/v1/file-explorer/{env}/sessions/{session_id}/stat
//   GET  /api/v1/file-explorer/{env}/sessions/{session_id}/requests/{request_id}
//   GET  /api/v1/file-explorer/{env}/sessions/{session_id}/requests/{request_id}/results
//
// Posture routes:
//   GET /api/v1/nodes/{env}/node/{uuid}/posture
//   GET /api/v1/nodes/{env}/node/{uuid}/posture/score
//   GET /api/v1/posture/profiles
//
// Saved queries routes:
//   GET    /api/v1/saved-queries/{env}
//   POST   /api/v1/saved-queries/{env}
//   PATCH  /api/v1/saved-queries/{env}/{name}
//   DELETE /api/v1/saved-queries/{env}/{name}
//
// Node logs routes:
//   GET /api/v1/logs/{type}/{env}/{uuid}

// FileExplorerSessionResponse mirrors the create-session response.
type FileExplorerSessionResponse struct {
	Session  fileexplorer.Session `json:"session"`
	NodeInfo ConsoleNodeInfo      `json:"node_info"`
}

// CreateFileExplorerSession opens a file explorer session against a node.
func (api *OsctrlAPI) CreateFileExplorerSession(env, uuid string) (FileExplorerSessionResponse, error) {
	var res FileExplorerSessionResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/file-explorer", env, "nodes", uuid, "sessions"))
	raw, err := api.PostGeneric(reqURL, nil)
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}

// CloseFileExplorerSession closes a file explorer session.
func (api *OsctrlAPI) CloseFileExplorerSession(env string, sessionID uint) error {
	var r struct {
		Message string `json:"message"`
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/file-explorer", env, "sessions", strconv.FormatUint(uint64(sessionID), 10)))
	raw, err := api.ReqGeneric("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("can not parse body - %w", err)
	}
	return nil
}

// SubmitFileExplorerList lists a directory path on the node.
func (api *OsctrlAPI) SubmitFileExplorerList(env string, sessionID uint, target string) (fileexplorer.Request, error) {
	return api.fileExplorerRequest(env, sessionID, "list", target)
}

// SubmitFileExplorerStat stats a path on the node.
func (api *OsctrlAPI) SubmitFileExplorerStat(env string, sessionID uint, target string) (fileexplorer.Request, error) {
	return api.fileExplorerRequest(env, sessionID, "stat", target)
}

func (api *OsctrlAPI) fileExplorerRequest(env string, sessionID uint, action, target string) (fileexplorer.Request, error) {
	var req fileexplorer.Request
	body := struct {
		Path string `json:"path"`
	}{Path: target}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return req, fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/file-explorer", env, "sessions", strconv.FormatUint(uint64(sessionID), 10), action))
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return req, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, fmt.Errorf("can not parse body - %w", err)
	}
	return req, nil
}

// GetFileExplorerRequest retrieves the current state of a file explorer request.
func (api *OsctrlAPI) GetFileExplorerRequest(env string, sessionID, requestID uint) (fileexplorer.Request, error) {
	var req fileexplorer.Request
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/file-explorer", env, "sessions", strconv.FormatUint(uint64(sessionID), 10),
			"requests", strconv.FormatUint(uint64(requestID), 10)))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return req, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, fmt.Errorf("can not parse body - %w", err)
	}
	return req, nil
}

// GetFileExplorerResults retrieves entries produced by a completed request.
func (api *OsctrlAPI) GetFileExplorerResults(env string, sessionID, requestID uint) ([]fileexplorer.Entry, error) {
	var entries []fileexplorer.Entry
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL,
		path.Join(APIPath, "/file-explorer", env, "sessions", strconv.FormatUint(uint64(sessionID), 10),
			"requests", strconv.FormatUint(uint64(requestID), 10), "results"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return entries, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return entries, fmt.Errorf("can not parse body - %w", err)
	}
	return entries, nil
}

// ─────────────────────────────── posture ───────────────────────────────

// GetNodePosture retrieves all posture categories for a node.
func (api *OsctrlAPI) GetNodePosture(env, uuid string) ([]posture.NodePosture, error) {
	var records []posture.NodePosture
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APINodes, env, "node", uuid, "posture"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return records, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		return records, fmt.Errorf("can not parse body - %w", err)
	}
	return records, nil
}

// GetNodePostureScore retrieves the SOC2/ISO27001 risk score for a node.
func (api *OsctrlAPI) GetNodePostureScore(env, uuid string) (posture.PostureScore, error) {
	var score posture.PostureScore
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APINodes, env, "node", uuid, "posture", "score"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return score, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &score); err != nil {
		return score, fmt.Errorf("can not parse body - %w", err)
	}
	return score, nil
}

// GetPostureProfiles lists the predefined posture profile templates.
func (api *OsctrlAPI) GetPostureProfiles() ([]posture.PostureProfile, error) {
	var profiles []posture.PostureProfile
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/posture", "profiles"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return profiles, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &profiles); err != nil {
		return profiles, fmt.Errorf("can not parse body - %w", err)
	}
	return profiles, nil
}

// ─────────────────────────────── saved queries ───────────────────────────────

// GetSavedQueries lists saved queries for an environment.
func (api *OsctrlAPI) GetSavedQueries(env string) ([]types.SavedQueryView, error) {
	var res types.SavedQueriesPagedResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/saved-queries", env))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("can not parse body - %w", err)
	}
	return res.Items, nil
}

// CreateSavedQuery saves a new query in an environment.
func (api *OsctrlAPI) CreateSavedQuery(env, name, query string) error {
	body := types.SavedQueryCreateRequest{Name: name, Query: query}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/saved-queries", env))
	raw, err := api.PostGeneric(reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// UpdateSavedQuery replaces the SQL body of an existing saved query.
func (api *OsctrlAPI) UpdateSavedQuery(env, name, query string) error {
	body := types.SavedQueryUpdateRequest{Query: query}
	jsonMessage, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("error marshaling data - %w", err)
	}
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/saved-queries", env, name))
	raw, err := api.ReqGeneric("PATCH", reqURL, bytes.NewReader(jsonMessage))
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// DeleteSavedQuery removes a saved query by name.
func (api *OsctrlAPI) DeleteSavedQuery(env, name string) error {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/saved-queries", env, name))
	raw, err := api.ReqGeneric("DELETE", reqURL, nil)
	if err != nil {
		return fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return nil
}

// ─────────────────────────────── node logs ───────────────────────────────

// GetNodeLogs retrieves recent result or status logs for a node.
// logType is "result" or "status".
func (api *OsctrlAPI) GetNodeLogs(env, logType, uuid string) (string, error) {
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/logs", logType, env, uuid))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	return string(raw), nil
}

// ─────────────────────────────── query samples ───────────────────────────────

// GetQuerySamples lists the built-in query sample templates.
func (api *OsctrlAPI) GetQuerySamples() ([]queries.QuerySample, error) {
	var samples []queries.QuerySample
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, APIQueries, "samples"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return samples, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &samples); err != nil {
		return samples, fmt.Errorf("can not parse body - %w", err)
	}
	return samples, nil
}

// GetFeatures retrieves the deployment feature switches.
func (api *OsctrlAPI) GetFeatures() (FeaturesResponse, error) {
	var res FeaturesResponse
	reqURL := fmt.Sprintf("%s%s", api.Configuration.URL, path.Join(APIPath, "/features"))
	raw, err := api.GetGeneric(reqURL, nil)
	if err != nil {
		return res, fmt.Errorf("error api request - %w - %s", err, string(raw))
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return res, fmt.Errorf("can not parse body - %w", err)
	}
	return res, nil
}

// FeaturesResponse mirrors the /features deployment switches.
type FeaturesResponse struct {
	Posture       bool `json:"posture"`
	ServiceConfig bool `json:"service_config"`
	LogSinks      bool `json:"log_sinks"`
	AuthProviders bool `json:"auth_providers"`
	Accelerated   bool `json:"accelerated"`
	Console       bool `json:"console"`
	FileExplorer  bool `json:"file_explorer"`
}
