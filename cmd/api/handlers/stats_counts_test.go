package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
)

// The stats endpoint reports active queries and carves per environment from
// one grouped count. Console and file-explorer rows share the table and must
// not be counted, nor finished queries.
func TestStatsHandlerActiveQueryAndCarveCounts(t *testing.T) {
	db, h, env, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, config.ServiceAPI, false)
	require.NoError(t, err)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, 0))

	for i, dq := range []queries.DistributedQuery{
		{Type: queries.StandardQueryType, Active: true},
		{Type: queries.StandardQueryType, Active: true},
		{Type: queries.StandardQueryType, Active: true, Completed: true},
		{Type: queries.CarveQueryType, Active: true},
		{Type: queries.ConsoleQueryType, Active: true},
		{Type: queries.FileExplorerQueryType, Active: true},
	} {
		dq.Name = fmt.Sprintf("stats_q%d", i)
		dq.Query = "SELECT 1;"
		dq.EnvironmentID = env.ID
		require.NoError(t, db.Create(&dq).Error)
	}

	rr := httptest.NewRecorder()
	h.StatsHandler(rr, consoleRequest(http.MethodGet, "/stats", nil, "alice"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var stats StatsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &stats))
	require.Len(t, stats.Environments, 1)
	require.Equal(t, 2, stats.Environments[0].ActiveQueries)
	require.Equal(t, 1, stats.Environments[0].ActiveCarves)
	require.Equal(t, 2, stats.TotalActiveQueries)
	require.Equal(t, 1, stats.TotalActiveCarves)
}
