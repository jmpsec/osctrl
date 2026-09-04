package main

import (
	"fmt"
	"github.com/jmpsec/osctrl/pkg/apiclient"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// shell_store_extras.go — additional DataStore surface covering the newer
// osctrl-api additions: console sessions, file explorer sessions, node
// posture, saved queries, node logs, and query samples. These are
// API-centric features (the console/file-explorer services live behind
// osctrl-api), so dbStore returns a clear "API mode" error for each.

// consoleStore is the API-backed surface for interactive per-node access.
type consoleStore interface {
	CreateConsoleSession(env, uuid string) (apiclient.ConsoleSessionResponse, error)
	GetConsoleSession(env string, sessionID uint) (console.Session, error)
	CloseConsoleSession(env string, sessionID uint) error
	SubmitConsoleCommand(env string, sessionID uint, input string, osqueryMode bool) (apiclient.ConsoleCommandResponse, error)
	GetConsoleCommand(env string, sessionID, commandID uint) (console.Command, error)
	GetConsoleCommandResults(env string, sessionID, commandID uint) ([]map[string]any, error)

	CreateFileExplorerSession(env, uuid string) (apiclient.FileExplorerSessionResponse, error)
	CloseFileExplorerSession(env string, sessionID uint) error
	SubmitFileExplorerList(env string, sessionID uint, path string) (fileexplorer.Request, error)
	SubmitFileExplorerStat(env string, sessionID uint, path string) (fileexplorer.Request, error)
	GetFileExplorerRequest(env string, sessionID, requestID uint) (fileexplorer.Request, error)
	GetFileExplorerResults(env string, sessionID, requestID uint) ([]fileexplorer.Entry, error)
}

// postureStore covers posture reads.
type postureStore interface {
	NodePosture(env, uuid string) ([]posture.NodePosture, error)
	NodePostureScore(env, uuid string) (posture.PostureScore, error)
	PostureProfiles() ([]posture.PostureProfile, error)
}

// savedStore covers saved-query CRUD.
type savedStore interface {
	SavedQueries(env string) ([]types.SavedQueryView, error)
	SaveQuery(env, name, query string) error
	UpdateSavedQuery(env, name, query string) error
	DeleteSavedQuery(env, name string) error
	QuerySamples() ([]queries.QuerySample, error)
	NodeLogs(env, logType, uuid string) (string, error)
}

// storeConsole casts the active store to the console surface when available.
func storeConsole(s DataStore) (consoleStore, error) {
	if cs, ok := s.(consoleStore); ok {
		return cs, nil
	}
	return nil, fmt.Errorf("console requires API mode")
}

// storePosture casts the active store to the posture surface when available.
func storePosture(s DataStore) (postureStore, error) {
	if ps, ok := s.(postureStore); ok {
		return ps, nil
	}
	return nil, fmt.Errorf("posture requires API mode")
}

// storeSaved casts the active store to the saved-query surface when available.
func storeSaved(s DataStore) (savedStore, error) {
	if ss, ok := s.(savedStore); ok {
		return ss, nil
	}
	return nil, fmt.Errorf("saved queries require API mode")
}

// ─────────────────────────────── apiStore implementations ───────────────────────────────

func (s *apiStore) CreateConsoleSession(env, uuid string) (apiclient.ConsoleSessionResponse, error) {
	return s.api.CreateConsoleSession(env, uuid)
}

func (s *apiStore) GetConsoleSession(env string, sessionID uint) (console.Session, error) {
	return s.api.GetConsoleSession(env, sessionID)
}

func (s *apiStore) CloseConsoleSession(env string, sessionID uint) error {
	return s.api.CloseConsoleSession(env, sessionID)
}

func (s *apiStore) SubmitConsoleCommand(env string, sessionID uint, input string, osqueryMode bool) (apiclient.ConsoleCommandResponse, error) {
	return s.api.SubmitConsoleCommand(env, sessionID, input, osqueryMode)
}

func (s *apiStore) GetConsoleCommand(env string, sessionID, commandID uint) (console.Command, error) {
	return s.api.GetConsoleCommand(env, sessionID, commandID)
}

func (s *apiStore) GetConsoleCommandResults(env string, sessionID, commandID uint) ([]map[string]any, error) {
	return s.api.GetConsoleCommandResults(env, sessionID, commandID)
}

func (s *apiStore) CreateFileExplorerSession(env, uuid string) (apiclient.FileExplorerSessionResponse, error) {
	return s.api.CreateFileExplorerSession(env, uuid)
}

func (s *apiStore) CloseFileExplorerSession(env string, sessionID uint) error {
	return s.api.CloseFileExplorerSession(env, sessionID)
}

func (s *apiStore) SubmitFileExplorerList(env string, sessionID uint, path string) (fileexplorer.Request, error) {
	return s.api.SubmitFileExplorerList(env, sessionID, path)
}

func (s *apiStore) SubmitFileExplorerStat(env string, sessionID uint, path string) (fileexplorer.Request, error) {
	return s.api.SubmitFileExplorerStat(env, sessionID, path)
}

func (s *apiStore) GetFileExplorerRequest(env string, sessionID, requestID uint) (fileexplorer.Request, error) {
	return s.api.GetFileExplorerRequest(env, sessionID, requestID)
}

func (s *apiStore) GetFileExplorerResults(env string, sessionID, requestID uint) ([]fileexplorer.Entry, error) {
	return s.api.GetFileExplorerResults(env, sessionID, requestID)
}

func (s *apiStore) NodePosture(env, uuid string) ([]posture.NodePosture, error) {
	return s.api.GetNodePosture(env, uuid)
}

func (s *apiStore) NodePostureScore(env, uuid string) (posture.PostureScore, error) {
	return s.api.GetNodePostureScore(env, uuid)
}

func (s *apiStore) PostureProfiles() ([]posture.PostureProfile, error) {
	return s.api.GetPostureProfiles()
}

func (s *apiStore) SavedQueries(env string) ([]types.SavedQueryView, error) {
	return s.api.GetSavedQueries(env)
}

func (s *apiStore) SaveQuery(env, name, query string) error {
	return s.api.CreateSavedQuery(env, name, query)
}

func (s *apiStore) UpdateSavedQuery(env, name, query string) error {
	return s.api.UpdateSavedQuery(env, name, query)
}

func (s *apiStore) DeleteSavedQuery(env, name string) error {
	return s.api.DeleteSavedQuery(env, name)
}

func (s *apiStore) QuerySamples() ([]queries.QuerySample, error) {
	return s.api.GetQuerySamples()
}

func (s *apiStore) NodeLogs(env, logType, uuid string) (string, error) {
	return s.api.GetNodeLogs(env, logType, uuid)
}
