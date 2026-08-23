package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
)

// fakeLogReader is a recording LogReader used to verify the handlers
// route reads through the wired LogReader instead of going straight to
// h.DB. It returns canned rows and records the calls so the test can
// assert the right arguments were passed.
type fakeLogReader struct {
	nodeLogsCalls    []fakeNodeLogsCall
	nodeLogsRows     []map[string]any
	queryResultsCall *fakeQueryResultsCall
	queryRows        []map[string]any
	streamCall       *string
	streamErr        error
}

type fakeNodeLogsCall struct {
	LogType, Env, UUID string
	Since              time.Time
	Limit              int
	Search             string
	Severity           string
}

type fakeQueryResultsCall struct {
	Env, Name  string
	Since      time.Time
	Page, Size int
}

func (f *fakeLogReader) NodeLogs(logType, env, uuid string, since time.Time, limit int, search string, severity string) ([]map[string]any, error) {
	f.nodeLogsCalls = append(f.nodeLogsCalls, fakeNodeLogsCall{logType, env, uuid, since, limit, search, severity})
	if f.nodeLogsRows == nil {
		return []map[string]any{}, nil
	}
	return f.nodeLogsRows, nil
}

func (f *fakeLogReader) QueryResults(env, name string, since time.Time, page, pageSize int) ([]map[string]any, int64, error) {
	f.queryResultsCall = &fakeQueryResultsCall{env, name, since, page, pageSize}
	return f.queryRows, int64(len(f.queryRows)), nil
}

func (f *fakeLogReader) StreamQueryResults(env, name string, fn func(logging.OsqueryQueryData) error) error {
	call := env + "/" + name
	f.streamCall = &call
	return f.streamErr
}

// mustEnvID resolves the env's numeric ID from its name so the test can
// create a query with the right EnvironmentID for the ownership gate.
func mustEnvID(t *testing.T, h *HandlersApi, envName string) uint {
	env, err := h.Envs.GetByName(envName)
	require.NoError(t, err)
	return env.ID
}

type logReaderTestEnv struct {
	h        *HandlersApi
	envName  string
	envUUID  string
	nodeUUID string
}

func setupLogReaderTest(t *testing.T) logReaderTestEnv {
	t.Helper()
	_, h, env, node := setupConsoleHandlers(t)
	// The NodeLogsHandler verifies node.Environment == env.Name. The
	// shared setupConsoleHandlers creates the node with Environment =
	// env.UUID ("env-uuid"), so align it to the env name the handler
	// expects.
	require.NoError(t, h.DB.Model(&node).Update("environment", env.Name).Error)
	node.Environment = env.Name
	// Wire the nil-guards the handler tests need: DebugHTTPConfig + AuditLog.
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	auditLog, err := auditlog.CreateAuditLogManager(h.DB, "api", false)
	require.NoError(t, err)
	h.AuditLog = auditLog
	return logReaderTestEnv{h: h, envName: env.Name, envUUID: env.UUID, nodeUUID: node.UUID}
}

func TestNodeLogsHandlerUsesLogReader(t *testing.T) {
	tc := setupLogReaderTest(t)

	fake := &fakeLogReader{
		nodeLogsRows: []map[string]any{
			{"line": "1", "message": "started", "uuid": tc.nodeUUID, "environment": tc.envName},
		},
	}
	tc.h.LogReader = fake

	req := consoleRequest(http.MethodGet, "/logs/status/env-uuid/NODE-UUID", nil, "alice")
	req.SetPathValue("type", "status")
	req.SetPathValue("env", tc.envName)
	req.SetPathValue("uuid", tc.nodeUUID)
	rr := httptest.NewRecorder()

	tc.h.NodeLogsHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	require.Len(t, fake.nodeLogsCalls, 1)
	call := fake.nodeLogsCalls[0]
	require.Equal(t, "status", call.LogType)
	require.Equal(t, tc.envName, call.Env)
	require.Equal(t, tc.nodeUUID, call.UUID)
	require.Equal(t, 100, call.Limit)
	require.Equal(t, "", call.Severity, "no severity param should pass empty string")
}

func TestNodeLogsHandlerPassesSeverityFilter(t *testing.T) {
	tc := setupLogReaderTest(t)

	fake := &fakeLogReader{
		nodeLogsRows: []map[string]any{
			{"line": "1", "message": "error", "uuid": tc.nodeUUID, "environment": tc.envName, "severity": "2"},
		},
	}
	tc.h.LogReader = fake

	req := consoleRequest(http.MethodGet, "/logs/status/env-uuid/NODE-UUID?severity=2", nil, "alice")
	req.SetPathValue("type", "status")
	req.SetPathValue("env", tc.envName)
	req.SetPathValue("uuid", tc.nodeUUID)
	rr := httptest.NewRecorder()

	tc.h.NodeLogsHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	require.Len(t, fake.nodeLogsCalls, 1)
	call := fake.nodeLogsCalls[0]
	require.Equal(t, "2", call.Severity, "severity query param should be passed to the reader")
}

func TestQueryResultsHandlerUsesLogReader(t *testing.T) {
	tc := setupLogReaderTest(t)
	// Create a query so the env-ownership gate passes.
	newQuery := queries.DistributedQuery{Name: "q-test", Creator: "alice", Active: true, EnvironmentID: mustEnvID(t, tc.h, tc.envName), Expected: 1}
	require.NoError(t, tc.h.Queries.Create(&newQuery))

	fake := &fakeLogReader{
		queryRows: []map[string]any{
			{"uuid": "NODE-UUID", "name": "q-test", "data": `{"result":[]}`, "status": 0},
		},
	}
	tc.h.LogReader = fake

	req := consoleRequest(http.MethodGet, "/queries/env-uuid/results/q-test", nil, "alice")
	req.SetPathValue("env", tc.envName)
	req.SetPathValue("name", "q-test")
	rr := httptest.NewRecorder()

	tc.h.QueryResultsHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	require.NotNil(t, fake.queryResultsCall)
	require.Equal(t, tc.envUUID, fake.queryResultsCall.Env)
	require.Equal(t, "q-test", fake.queryResultsCall.Name)
	require.Equal(t, 1, fake.queryResultsCall.Page)
	require.Equal(t, 100, fake.queryResultsCall.Size)
}
