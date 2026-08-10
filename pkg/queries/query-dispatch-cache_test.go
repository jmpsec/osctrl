package queries

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/nodes"
)

// ──────────────────────────────────────────────────────────────────────────────
// Fake Redis for testing — supports GET, SET, DEL, PING, and pipelines.
// ──────────────────────────────────────────────────────────────────────────────

type fakeRedisStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newFakeRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	store := &fakeRedisStore{values: make(map[string]string)}

	client := redis.NewClient(&redis.Options{
		Addr:     "fake-redis",
		PoolSize: 1,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			go serveFakeRedis(serverConn, store)
			return clientConn, nil
		},
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func serveFakeRedis(conn net.Conn, store *fakeRedisStore) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			return
		}
		handleFakeRedisCmd(conn, store, args)
	}
}

func handleFakeRedisCmd(conn net.Conn, store *fakeRedisStore, args []string) {
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "GET":
		store.mu.Lock()
		val, ok := store.values[args[1]]
		store.mu.Unlock()
		if !ok {
			_, _ = conn.Write([]byte("$-1\r\n"))
		} else {
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(val), val)
		}
	case "SET":
		store.mu.Lock()
		store.values[args[1]] = args[2]
		store.mu.Unlock()
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "DEL":
		n := 0
		store.mu.Lock()
		for _, k := range args[1:] {
			if _, ok := store.values[k]; ok {
				delete(store.values, k)
				n++
			}
		}
		store.mu.Unlock()
		_, _ = fmt.Fprintf(conn, ":%d\r\n", n)
	case "PING":
		_, _ = conn.Write([]byte("+PONG\r\n"))
	default:
		_, _ = fmt.Fprintf(conn, "-ERR unsupported %q\r\n", cmd)
	}
}

func readRESPArray(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	count, err := strconv.Atoi(strings.TrimPrefix(line, "*"))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		header = strings.TrimSuffix(strings.TrimSuffix(header, "\n"), "\r")
		size, err := strconv.Atoi(strings.TrimPrefix(header, "$"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&DistributedQuery{}, &NodeQuery{}, &DistributedQueryTarget{}))
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	return db
}

func setupQueries(t *testing.T, db *gorm.DB) *Queries {
	t.Helper()
	q := CreateQueries(db)
	require.NotNil(t, q)
	return q
}

// NodeQueries with a nil cache should behave exactly as before — always
// hits the DB.
func TestNodeQueries_NilCache_FallsBackToDB(t *testing.T) {
	db := setupTestDB(t)
	q := setupQueries(t, db)
	q.Cache = nil // explicitly nil

	node := nodes.OsqueryNode{UUID: "test-uuid", NodeKey: "test-key", Hostname: "test-host"}
	require.NoError(t, db.Create(&node).Error)

	result, accelerate, err := q.NodeQueries(node)
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.False(t, accelerate)
}

// NodeQueries with a cache should cache empty results and skip the DB
// on the second call.
func TestNodeQueries_CacheSkipsDB_WhenEmpty(t *testing.T) {
	db := setupTestDB(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	node := nodes.OsqueryNode{UUID: "test-uuid", NodeKey: "test-key", Hostname: "test-host"}
	require.NoError(t, db.Create(&node).Error)

	// First call — hits DB, caches empty result.
	result, _, err := q.NodeQueries(node)
	require.NoError(t, err)
	assert.Empty(t, result)

	// Verify the cache has the "no queries" entry.
	cached, err := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.NoError(t, err)
	assert.True(t, cached, "cache should know this node has no pending queries")
}

// CreateNodeQueries should invalidate the cache for targeted nodes.
func TestCreateNodeQueries_InvalidatesCache(t *testing.T) {
	db := setupTestDB(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	// Create a node.
	node := nodes.OsqueryNode{UUID: "test-uuid", NodeKey: "test-key", Hostname: "test-host"}
	require.NoError(t, db.Create(&node).Error)

	// Prime the cache with "no queries pending."
	q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	cached, err := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.NoError(t, err)
	assert.True(t, cached)

	// Create a query and link it to the node.
	dq := DistributedQuery{
		Name: "test-query", Query: "SELECT 1", Type: "query",
		EnvironmentID: 1, Active: true,
	}
	require.NoError(t, q.Create(&dq))
	require.NoError(t, q.CreateNodeQueries([]uint{node.ID}, dq.ID))

	// Cache should be invalidated.
	cached, err = q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.NoError(t, err)
	assert.False(t, cached, "cache should be invalidated after CreateNodeQueries")

	// Next NodeQueries call should hit the DB and find the query.
	result, _, err := q.NodeQueries(node)
	require.NoError(t, err)
	assert.Contains(t, result, "test-query")
}

// CreateNodeQueries should invalidate the cache for many nodes at once.
func TestCreateNodeQueries_InvalidatesManyNodes(t *testing.T) {
	db := setupTestDB(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	// Create 5 nodes and prime the cache for all.
	var nodeIDs []uint
	for i := 0; i < 5; i++ {
		node := nodes.OsqueryNode{
			UUID: fmt.Sprintf("uuid-%d", i), NodeKey: fmt.Sprintf("key-%d", i),
			Hostname: fmt.Sprintf("host-%d", i),
		}
		require.NoError(t, db.Create(&node).Error)
		nodeIDs = append(nodeIDs, node.ID)
		q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	}

	// All should be cached.
	for _, id := range nodeIDs {
		cached, _ := q.Cache.HasNoPendingQueries(context.Background(), id)
		assert.True(t, cached)
	}

	// Create a query targeting all nodes.
	dq := DistributedQuery{Name: "bulk-query", Query: "SELECT 1", Type: "query", EnvironmentID: 1, Active: true}
	require.NoError(t, q.Create(&dq))
	require.NoError(t, q.CreateNodeQueries(nodeIDs, dq.ID))

	// All should be invalidated.
	for _, id := range nodeIDs {
		cached, _ := q.Cache.HasNoPendingQueries(context.Background(), id)
		assert.False(t, cached, "node %d cache should be invalidated", id)
	}
}

// A nil cache should be a complete no-op — no panics.
func TestQueryDispatchCache_NilCacheIsNoOp(t *testing.T) {
	var c *QueryDispatchCache

	ok, err := c.HasNoPendingQueries(context.Background(), 1)
	assert.False(t, ok)
	assert.NoError(t, err)

	// These should not panic.
	c.SetNoPendingQueries(context.Background(), 1)
	c.Invalidate(context.Background(), 1)
	c.InvalidateMany(context.Background(), []uint{1, 2, 3})
}

// uintToStr should produce correct decimal strings.
func TestUintToStr(t *testing.T) {
	assert.Equal(t, "0", uintToStr(0))
	assert.Equal(t, "1", uintToStr(1))
	assert.Equal(t, "42", uintToStr(42))
	assert.Equal(t, "12345", uintToStr(12345))
	assert.Equal(t, "99999", uintToStr(99999))
}

// Cache miss (Redis Nil) should return ok=false, not an error.
func TestQueryDispatchCache_MissReturnsFalse(t *testing.T) {
	client := newFakeRedisClient(t)
	c := NewQueryDispatchCache(client, 10*time.Second)

	ok, err := c.HasNoPendingQueries(context.Background(), 999)
	require.NoError(t, err)
	assert.False(t, ok)
}
