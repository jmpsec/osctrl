package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCreateQueryInvalidatesDispatchAfterCommit(t *testing.T) {
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to a disposable Redis instance")
	}
	for _, name := range []string{"commit", "rollback", "canceled-request"} {
		t.Run(name, func(t *testing.T) {
			rollback := name == "rollback"
			db, h, env, node := setupConsoleHandlers(t)
			h.AuditLog = &auditlog.AuditLogManager{}
			h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
			client := redis.NewClient(&redis.Options{Addr: addr})
			t.Cleanup(func() { _ = client.Close() })
			h.Queries.Cache = queries.NewQueryDispatchCache(client, 0)
			h.Queries.Cache.Invalidate(context.Background(), node.ID)
			t.Cleanup(func() { h.Queries.Cache.Invalidate(context.Background(), node.ID) })
			result, _, err := h.Queries.NodeQueries(node)
			require.NoError(t, err)
			require.Empty(t, result)
			cached, err := h.Queries.Cache.HasNoPendingQueries(context.Background(), node.ID)
			require.NoError(t, err)
			require.True(t, cached)

			body, err := json.Marshal(types.ApiDistributedQueryRequest{Query: "SELECT 1", UUIDs: []string{node.UUID}})
			require.NoError(t, err)
			req := consoleRequest(http.MethodPost, "/queries", body, "alice")
			requestCtx, cancel := context.WithCancel(req.Context())
			defer cancel()
			req = req.WithContext(requestCtx)
			req.SetPathValue("env", env.Name)
			checkedBeforeCommit := false
			require.NoError(t, db.Callback().Create().Before("gorm:create").Register("test:before_target", func(tx *gorm.DB) {
				if tx.Statement.Table != "distributed_query_targets" {
					return
				}
				checkedBeforeCommit = true
				cached, err := h.Queries.Cache.HasNoPendingQueries(context.Background(), node.ID)
				require.NoError(t, err)
				require.True(t, cached, "do not invalidate while query creation is uncommitted")
				if rollback {
					tx.AddError(errors.New("target write failed"))
				}
				if name == "canceled-request" {
					cancel()
				}
			}))
			rr := httptest.NewRecorder()
			h.QueriesRunHandler(rr, req)
			require.True(t, checkedBeforeCommit, rr.Body.String())
			cached, err = h.Queries.Cache.HasNoPendingQueries(context.Background(), node.ID)
			require.NoError(t, err)
			if rollback {
				require.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
				require.True(t, cached, "rollback must preserve the idle hint")
				var count int64
				require.NoError(t, db.Model(&queries.NodeQuery{}).Count(&count).Error)
				require.Zero(t, count)
				return
			}
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			require.False(t, cached, "commit must invalidate the idle hint")
			var response types.ApiQueriesResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
			result, _, err = h.Queries.NodeQueries(node)
			require.NoError(t, err)
			require.Equal(t, queries.QueryReadQueries{response.Name: "SELECT 1"}, result)
		})
	}
}
