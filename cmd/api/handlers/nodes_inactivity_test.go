package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestNodeConsumersEnvironmentThresholds(t *testing.T) {
	db, h, env, node := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	var err error
	h.AuditLog, err = auditlog.CreateAuditLogManager(db, config.ServiceAPI, false)
	require.NoError(t, err)
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, 0))
	require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 2, env.ID))
	node.Environment = env.Name
	node.LastSeen = time.Now().Add(-48 * time.Hour)
	require.NoError(t, db.Save(&node).Error)
	fixtures := []nodes.OsqueryNode{node}
	envFixtures := []environments.TLSEnvironment{env}
	for _, name := range []string{"long", "inherited"} {
		e := h.Envs.Empty(name, name+".example.com")
		require.NoError(t, h.Envs.Create(&e))
		if name == "long" {
			require.NoError(t, h.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 168, e.ID))
		}
		n := nodes.OsqueryNode{UUID: name, Environment: e.Name, EnvironmentID: e.ID, LastSeen: node.LastSeen}
		require.NoError(t, db.Create(&n).Error)
		fixtures = append(fixtures, n)
		envFixtures = append(envFixtures, e)
		require.NoError(t, h.Users.CreatePermission(users.UserPermission{Username: "alice", AccessType: int(users.AdminLevel), AccessValue: true, Environment: e.UUID, EnvironmentID: e.ID}))
	}

	// A batch must read settings once per distinct environment, even for repeated nodes.
	reads := 0
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("count_inactivity_reads", func(tx *gorm.DB) {
		if tx.Statement.Table == "setting_values" {
			reads++
		}
	}))
	batch := h.projectNodesWithGeo(append(fixtures, fixtures[0]))
	require.Equal(t, 3, reads)
	require.NoError(t, db.Callback().Query().Remove("count_inactivity_reads"))
	for i, want := range []string{"offline", "healthy", "offline"} {
		require.Equal(t, want, batch[i].Health.Status)
		require.Equal(t, want, h.projectNode(fixtures[i]).Health.Status)
	}

	for i, e := range envFixtures {
		for _, tc := range []struct {
			name    string
			handler http.HandlerFunc
			active  bool
			paged   bool
		}{
			{"active", h.ActiveNodesHandler, true, false},
			{"inactive", h.InactiveNodesHandler, false, false},
			{"active", h.NodesPagedHandler, true, true},
			{"inactive", h.NodesPagedHandler, false, true},
		} {
			req := consoleRequest(http.MethodGet, "/nodes?status="+tc.name, nil, "alice")
			req.SetPathValue("env", e.Name)
			rr := httptest.NewRecorder()
			tc.handler(rr, req)
			want := int64(0)
			if tc.active == (i == 1) {
				want = 1
			}
			if tc.paged {
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				var page types.NodesPagedResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &page))
				require.Equal(t, want, page.TotalItems)
			} else if want == 0 {
				require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
			} else {
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				var got []nodes.OsqueryNode
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
				require.Len(t, got, 1)
				require.Equal(t, fixtures[i].ID, got[0].ID)
			}
		}
	}

	rr := httptest.NewRecorder()
	h.StatsHandler(rr, consoleRequest(http.MethodGet, "/stats", nil, "alice"))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var stats apiclient.StatsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &stats))
	require.Equal(t, int64(24), stats.InactiveHours)
	require.Equal(t, int64(1), stats.ActiveNodes)
	require.Equal(t, int64(2), stats.InactiveNodes)
	require.Len(t, stats.Environments, 3)
	for _, e := range stats.Environments {
		require.Equal(t, map[string]int64{env.Name: 2, "long": 168, "inherited": 24}[e.Name], e.InactiveHours)
		require.Equal(t, int64(1), e.TotalNodes)
		if e.Name == "long" {
			require.Equal(t, int64(1), e.ActiveNodes)
		} else {
			require.Equal(t, int64(1), e.InactiveNodes)
		}
	}

	// Threshold changes must not grant access to other environments.
	rr = httptest.NewRecorder()
	h.StatsHandler(rr, consoleRequest(http.MethodGet, "/stats", nil, "bob"))
	require.Equal(t, http.StatusOK, rr.Code)
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &stats))
	require.Empty(t, stats.Environments)
}
