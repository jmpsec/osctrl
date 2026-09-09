package handlers

import (
	"context"
	"os"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSessionHintsReduceSQLAndFollowSessionLifecycle(t *testing.T) {
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to run Redis session hint integration tests")
	}
	for _, kind := range []string{"console", "fileexplorer"} {
		t.Run(kind, func(t *testing.T) {
			client := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
			t.Cleanup(func() { _ = client.Close() })
			require.NoError(t, client.Ping(context.Background()).Err())
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			require.NoError(t, err)
			queryManager := queries.CreateQueries(db)
			cm := console.NewManager(db, queryManager)
			fm := fileexplorer.NewManager(db, queryManager)
			cm.SessionHints = cache.NewSessionHints(client)
			fm.SessionHints = cache.NewSessionHints(client)
			h := CreateHandlersTLS(WithQueries(queryManager), WithSessionHints(cache.NewSessionHints(client)),
				WithOsqueryValues(&config.YAMLConfigurationOsquery{Accelerated: true, Console: true, FileExplorer: true}))
			env := environments.TLSEnvironment{ID: 1, UUID: "env"}
			node := nodes.OsqueryNode{ID: 7, UUID: uuid.NewString(), EnvironmentID: 1}
			reads := 0
			require.NoError(t, db.Callback().Query().Before("gorm:query").Register("count_session_reads", func(tx *gorm.DB) {
				if tx.Statement.Table == "console_sessions" || tx.Statement.Table == "file_explorer_sessions" {
					reads++
				}
			}))
			for range 10 {
				require.False(t, h.shouldAccelerateQueryRead(node, false))
			}
			require.Equal(t, 2, reads, "idle polls should read each session table only once")
			create := func() uint {
				if kind == "console" {
					s, err := cm.CreateSession(env, node, "alice")
					require.NoError(t, err)
					return s.ID
				}
				s, err := fm.CreateSession(env, node, "alice")
				require.NoError(t, err)
				return s.ID
			}
			touch := func(id uint) {
				if kind == "console" {
					_, err := cm.TouchSession(id)
					require.NoError(t, err)
				} else {
					_, err := fm.TouchSession(id)
					require.NoError(t, err)
				}
			}
			closeSession := cm.CloseSession
			var model any = &console.Session{}
			if kind == "fileexplorer" {
				closeSession = fm.CloseSession
				model = &fileexplorer.Session{}
			}
			id := create()
			require.True(t, h.shouldAccelerateQueryRead(node, false), "create must invalidate absence")
			reads = 0
			for range 10 {
				require.True(t, h.shouldAccelerateQueryRead(node, false))
			}
			require.Zero(t, reads, "warm active hints must also skip SQL")
			for _, other := range []nodes.OsqueryNode{
				{ID: 8, UUID: node.UUID, EnvironmentID: 1},
				{ID: 7, UUID: node.UUID + "-other", EnvironmentID: 1},
				{ID: 7, UUID: node.UUID, EnvironmentID: 2},
			} {
				require.False(t, h.shouldAccelerateQueryRead(other, false), "all node identity fields must be scoped")
			}
			require.NoError(t, db.Model(model).Where("id = ?", id).UpdateColumn("updated_at", time.Now().Add(-time.Minute)).Error)
			h.SessionHints.Invalidate(context.Background(), kind, env.ID, node.ID, node.UUID)
			require.False(t, h.shouldAccelerateQueryRead(node, false))
			touch(id)
			require.True(t, h.shouldAccelerateQueryRead(node, false), "refresh must invalidate stale absence")
			second := create()
			require.NoError(t, closeSession(id))
			require.True(t, h.shouldAccelerateQueryRead(node, false), "closing one session must preserve the other")
			require.NoError(t, closeSession(second))
			require.False(t, h.shouldAccelerateQueryRead(node, false), "close must invalidate presence")
			touch(second)
			require.False(t, h.shouldAccelerateQueryRead(node, false), "refresh must not revive a closed session")
			third := create()
			require.NoError(t, client.Close())
			require.True(t, h.shouldAccelerateQueryRead(node, false), "Redis failure must use SQL")
			require.NoError(t, closeSession(third), "Redis failure must not fail a committed close")
			require.False(t, h.shouldAccelerateQueryRead(node, false))
			deleted := create()
			require.NoError(t, db.Delete(model, deleted).Error)
			require.False(t, h.shouldAccelerateQueryRead(node, false), "SQL fallback must exclude soft-deleted sessions")
		})
	}
}
