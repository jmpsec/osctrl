package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestQueriesRunHandlerCreatesPendingNodeQueryForUUIDTarget(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	auditLog, err := auditlog.CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	h.AuditLog = auditLog

	body, err := json.Marshal(types.ApiDistributedQueryRequest{
		Query:    "select * from os_version;",
		UUIDs:    []string{node.UUID},
		ExpHours: 24,
	})
	require.NoError(t, err)

	req := consoleRequest(http.MethodPost, "/queries", body, "alice")
	req.SetPathValue("env", env.Name)
	rr := httptest.NewRecorder()

	h.QueriesRunHandler(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.ApiQueriesResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", resp.Name).First(&distributed).Error)
	require.Equal(t, 1, distributed.Expected)
	require.True(t, distributed.Expiration.After(time.Now().Add(23*time.Hour)))

	var nodeQuery queries.NodeQuery
	require.NoError(t, db.Where("node_id = ? AND query_id = ?", node.ID, distributed.ID).First(&nodeQuery).Error)
	require.Equal(t, queries.DistributedQueryStatusPending, nodeQuery.Status)
}

func TestQueriesActionHandlerRejectsUnknownAction(t *testing.T) {
	db, h, env, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	auditLog, err := auditlog.CreateAuditLogManager(db, "api", true)
	require.NoError(t, err)
	h.AuditLog = auditLog

	query := queries.DistributedQuery{
		Name:          "query-action-test",
		Active:        true,
		EnvironmentID: env.ID,
	}
	require.NoError(t, h.Queries.Create(&query))

	req := consoleRequest(http.MethodPost, "/queries", nil, "alice")
	req.SetPathValue("env", env.Name)
	req.SetPathValue("action", "unknown")
	req.SetPathValue("name", query.Name)
	rr := httptest.NewRecorder()

	h.QueriesActionHandler(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	var resp types.ApiErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.Equal(t, "invalid action", resp.Error)

	var persisted queries.DistributedQuery
	require.NoError(t, db.First(&persisted, query.ID).Error)
	require.True(t, persisted.Active)
	require.False(t, persisted.Completed)
	require.False(t, persisted.Deleted)
	require.False(t, persisted.Expired)

	var auditEntries int64
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Count(&auditEntries).Error)
	require.Zero(t, auditEntries)
}
