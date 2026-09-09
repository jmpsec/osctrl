package queries

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
)

func dispatchRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("OSCTRL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set OSCTRL_TEST_REDIS_ADDR to a disposable Redis instance")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())
	return client
}

func TestQueryDispatchRedisInvalidationDuringFill(t *testing.T) {
	for _, name := range []string{"single", "many", "expired-invalidation"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			reader := NewQueryDispatchCache(dispatchRedisClient(t), 0)
			writer := NewQueryDispatchCache(dispatchRedisClient(t), 0)
			if name == "expired-invalidation" {
				writer.ttl = 20 * time.Millisecond
			}
			db := setupTestDB(t)
			q := setupQueries(t, db)
			q.Cache = writer
			node := nodes.OsqueryNode{ID: uint(time.Now().UnixNano())}
			t.Cleanup(func() { _ = reader.client.Del(ctx, cacheKey(node.ID)).Err() })
			dq := DistributedQuery{Name: "race-query", Query: "SELECT 1", Type: ConsoleQueryType, Active: true}
			require.NoError(t, q.Create(&dq))

			// The reader's SQL snapshot is empty; a writer commits and invalidates
			// before the reader attempts to cache that snapshot.
			_, _, err := reader.read(ctx, node.ID, func() (QueryReadQueries, bool, error) {
				if name == "many" {
					require.NoError(t, q.CreateNodeQueries([]uint{node.ID}, dq.ID))
				} else {
					require.NoError(t, db.Create(&NodeQuery{NodeID: node.ID, QueryID: dq.ID}).Error)
					writer.Invalidate(ctx, node.ID)
				}
				if name == "expired-invalidation" {
					require.Eventually(t, func() bool {
						count, err := writer.client.Exists(ctx, cacheKey(node.ID)).Result()
						return err == nil && count == 0
					}, 2*time.Second, 10*time.Millisecond)
				}
				return QueryReadQueries{}, false, nil
			})
			require.NoError(t, err)
			cached, err := reader.HasNoPendingQueries(ctx, node.ID)
			require.NoError(t, err)
			require.False(t, cached)
			q.Cache = reader
			result, accelerate, err := q.NodeQueries(node)
			require.NoError(t, err)
			require.Equal(t, QueryReadQueries{"race-query": "SELECT 1"}, result)
			require.True(t, accelerate)
		})
	}
}

func TestQueryDispatchRedisExpiryAndClientRestart(t *testing.T) {
	ctx := context.Background()
	client := dispatchRedisClient(t)
	nodeID := uint(time.Now().UnixNano())
	t.Cleanup(func() { _ = client.Del(ctx, cacheKey(nodeID)).Err() })
	cache := NewQueryDispatchCache(client, 0)
	reads := 0
	load := func() (QueryReadQueries, bool, error) { reads++; return QueryReadQueries{}, false, nil }
	_, _, err := cache.read(ctx, nodeID, load)
	require.NoError(t, err)
	ttl, err := client.PTTL(ctx, cacheKey(nodeID)).Result()
	require.NoError(t, err)
	require.Greater(t, ttl, time.Minute)
	require.LessOrEqual(t, ttl, 2*time.Minute)
	cache = NewQueryDispatchCache(dispatchRedisClient(t), 50*time.Millisecond)
	_, _, err = cache.read(ctx, nodeID, load)
	require.NoError(t, err)
	require.Equal(t, 1, reads, "new process must reuse the shared empty hint")
	cache.Invalidate(ctx, nodeID)
	_, _, err = cache.read(ctx, nodeID, load)
	require.NoError(t, err)
	require.Equal(t, 2, reads)
	require.Eventually(t, func() bool {
		cached, err := cache.HasNoPendingQueries(ctx, nodeID)
		return err == nil && !cached
	}, 2*time.Second, 10*time.Millisecond)
	_, _, err = cache.read(ctx, nodeID, load)
	require.NoError(t, err)
	require.Equal(t, 3, reads, "expiry must force a fresh lookup")
	require.NoError(t, cache.client.Close())
	_, _, err = cache.read(ctx, nodeID, load)
	require.NoError(t, err)
	require.Equal(t, 4, reads, "Redis failure must fall back to SQL")
}

func TestQueryDispatchRedisRestartDuringFill(t *testing.T) {
	container := os.Getenv("OSCTRL_TEST_REDIS_CONTAINER")
	if container == "" {
		t.Skip("set OSCTRL_TEST_REDIS_CONTAINER to a disposable Redis container without persistence and with a fixed host port")
	}
	ctx := context.Background()
	client := dispatchRedisClient(t)
	cache := NewQueryDispatchCache(client, 0)
	nodeID := uint(time.Now().UnixNano())
	t.Cleanup(func() { _ = client.Del(ctx, cacheKey(nodeID)).Err() })
	_, _, err := cache.read(ctx, nodeID, func() (QueryReadQueries, bool, error) {
		output, err := exec.Command("docker", "restart", container).CombinedOutput()
		require.NoError(t, err, "%s", output)
		return QueryReadQueries{}, false, nil
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return client.Ping(ctx).Err() == nil }, 5*time.Second, 20*time.Millisecond)
	cached, err := cache.HasNoPendingQueries(ctx, nodeID)
	require.NoError(t, err)
	require.False(t, cached, "a lost WATCH connection must not repopulate Redis with an old result")
	reads := 0
	_, _, err = cache.read(ctx, nodeID, func() (QueryReadQueries, bool, error) {
		reads++
		return QueryReadQueries{}, false, nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, reads)
	cached, err = cache.HasNoPendingQueries(ctx, nodeID)
	require.NoError(t, err)
	require.True(t, cached, "fresh lookups should refill after Redis restarts")
}
