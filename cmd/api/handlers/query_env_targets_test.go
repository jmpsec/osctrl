package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// setupEnvTargets adds environment "other" (other-uuid) with one node.
// "legacy" holds query/carve on env-uuid plus leftover name-keyed rows on
// "other" while its other-uuid rows are revoked; "granted" holds query/carve
// on both UUIDs.
func setupEnvTargets(t *testing.T) (*HandlersApi, nodes.OsqueryNode) {
	t.Helper()
	db, h, env, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	auditLog, err := auditlog.CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	h.AuditLog = auditLog
	other := environments.TLSEnvironment{UUID: "other-uuid", Name: "other"}
	require.NoError(t, db.Create(&other).Error)
	node := nodes.OsqueryNode{UUID: "OTHER-NODE", Platform: "linux", EnvironmentID: other.ID, Environment: other.Name, LastSeen: time.Now()}
	require.NoError(t, db.Create(&node).Error)
	grant := func(user, environment string, value bool) {
		for _, level := range []users.AccessLevel{users.QueryLevel, users.CarveLevel} {
			require.NoError(t, h.Users.CreatePermission(users.UserPermission{Username: user, Environment: environment, AccessType: int(level), AccessValue: value}))
		}
	}
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "legacy"}))
	grant("legacy", env.UUID, true)
	grant("legacy", "other", true)
	grant("legacy", "other-uuid", false)
	require.NoError(t, h.Users.Create(users.AdminUser{Username: "granted"}))
	grant("granted", env.UUID, true)
	grant("granted", "other-uuid", true)
	return h, node
}

func runTargeted(t *testing.T, h *HandlersApi, carve bool, user string, envs []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.ApiDistributedQueryRequest{Query: "select 1;", Path: "/etc/hosts", Environments: envs})
	require.NoError(t, err)
	req := consoleRequest(http.MethodPost, "/run", body, user)
	req.SetPathValue("env", "env")
	rr := httptest.NewRecorder()
	if carve {
		h.CarvesRunHandler(rr, req)
	} else {
		h.QueriesRunHandler(rr, req)
	}
	return rr
}

func TestRunTargetEnvironmentsAuthorizedByUUID(t *testing.T) {
	for _, carve := range []bool{false, true} {
		name := map[bool]string{false: "query", true: "carve"}[carve]
		t.Run(name+" name-keyed row refused", func(t *testing.T) {
			h, _ := setupEnvTargets(t)
			for _, target := range []string{"other", "other-uuid"} {
				rr := runTargeted(t, h, carve, "legacy", []string{target})
				require.Equal(t, http.StatusForbidden, rr.Code, target+" "+rr.Body.String())
				require.Contains(t, rr.Body.String(), "insufficient permissions")
				require.Contains(t, rr.Body.String(), "environment "+target)
			}
		})
		t.Run(name+" uuid grant works by name and uuid", func(t *testing.T) {
			h, node := setupEnvTargets(t)
			for _, target := range []string{"other", "other-uuid"} {
				rr := runTargeted(t, h, carve, "granted", []string{target})
				require.Less(t, rr.Code, 300, target+" "+rr.Body.String())
				var resp types.ApiQueriesResponse
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
				var nq queries.NodeQuery
				require.NoError(t, h.DB.Joins("JOIN distributed_queries ON distributed_queries.id = node_queries.query_id").
					Where("distributed_queries.name = ? AND node_queries.node_id = ?", resp.Name, node.ID).First(&nq).Error, target)
			}
		})
		t.Run(name+" unknown environment is 404", func(t *testing.T) {
			h, _ := setupEnvTargets(t)
			rr := runTargeted(t, h, carve, "granted", []string{"nope"})
			require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
			require.Contains(t, rr.Body.String(), "environment not found: nope")
		})
	}
}
