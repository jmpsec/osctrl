package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestPollingDoesNotCreateAuditRows(t *testing.T) {
	db, h, env, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, config.ServiceAPI, true)
	require.NoError(t, err)
	for _, handler := range []http.HandlerFunc{h.NodesPagedHandler, h.QueryListHandler, h.CarveListHandler} {
		for i := 0; i < 3; i++ {
			r := consoleRequest(http.MethodGet, "/poll", nil, "alice")
			r.SetPathValue("env", env.Name)
			r.SetPathValue("target", "all")
			w := httptest.NewRecorder()
			handler(w, r)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		}
	}
	var count int64
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestEnvActivityCountsOnlySuccessfulEnrollments(t *testing.T) {
	db, h, env, _ := setupConsoleHandlers(t)
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, config.ServiceAPI, true)
	require.NoError(t, err)
	h.AuditLog.NodeAction("alice", "viewed paged nodes", "", env.ID)
	h.AuditLog.NodeAction("alice", "deleted node", "", env.ID)
	h.AuditLog.FailedEnroll("", env.Name, "invalid secret", env.ID)
	h.AuditLog.Denied("alice", "/nodes", "", "forbidden", auditlog.LogTypeNode, env.ID)
	h.AuditLog.QueryAction("alice", "complete query", "", env.ID)
	h.AuditLog.NewEnroll("NODE", "", env.ID)
	h.AuditLog.NewEnroll("OTHER-ENV", "", env.ID+1)
	r := consoleRequest(http.MethodGet, "/activity", nil, "alice")
	r.SetPathValue("env", env.Name)
	w := httptest.NewRecorder()
	h.EnvActivityHandler(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var buckets []ActivityBucket
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &buckets))
	var enrolls, queries int
	for _, bucket := range buckets {
		enrolls += bucket.Enroll
		queries += bucket.Query
	}
	require.Equal(t, 1, enrolls)
	require.Equal(t, 1, queries)
}
