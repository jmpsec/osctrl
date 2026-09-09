package queries

import (
	"bufio"
	"bytes"
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
	mu       sync.Mutex
	values   map[string]string
	versions map[string]int
	expires  map[string]time.Duration
	now      time.Duration
}

func newFakeRedisClient(t *testing.T) *redis.Client {
	client, _ := newFakeRedis(t)
	return client
}

func newFakeRedis(t *testing.T) (*redis.Client, *fakeRedisStore) {
	t.Helper()
	store := &fakeRedisStore{values: make(map[string]string), versions: make(map[string]int), expires: make(map[string]time.Duration)}

	client := redis.NewClient(&redis.Options{
		Addr:     "fake-redis",
		PoolSize: 4,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			serverConn, clientConn := net.Pipe()
			go serveFakeRedis(serverConn, store)
			return clientConn, nil
		},
	})
	t.Cleanup(func() { _ = client.Close() })
	return client, store
}

func serveFakeRedis(conn net.Conn, store *fakeRedisStore) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	watched := make(map[string]int)
	var queued [][]string
	inTransaction := false
	for {
		args, err := readRESPArray(reader)
		if err != nil {
			return
		}
		if len(args) == 0 {
			return
		}
		store.mu.Lock()
		for key, expires := range store.expires {
			if store.now >= expires {
				delete(store.values, key)
				delete(store.expires, key)
				store.versions[key]++
			}
		}
		var response bytes.Buffer
		switch strings.ToUpper(args[0]) {
		case "WATCH":
			for _, key := range args[1:] {
				watched[key] = store.versions[key]
			}
			response.WriteString("+OK\r\n")
		case "UNWATCH":
			clear(watched)
			response.WriteString("+OK\r\n")
		case "MULTI":
			inTransaction = true
			response.WriteString("+OK\r\n")
		case "EXEC":
			conflict := false
			for key, version := range watched {
				conflict = conflict || store.versions[key] != version
			}
			if conflict {
				response.WriteString("*-1\r\n")
			} else {
				fmt.Fprintf(&response, "*%d\r\n", len(queued))
				for _, command := range queued {
					handleFakeRedisCmd(&response, store, command)
				}
			}
			clear(watched)
			queued = nil
			inTransaction = false
		default:
			if inTransaction {
				queued = append(queued, args)
				response.WriteString("+QUEUED\r\n")
			} else {
				handleFakeRedisCmd(&response, store, args)
			}
		}
		store.mu.Unlock()
		_, _ = conn.Write(response.Bytes())
	}
}

func handleFakeRedisCmd(conn io.Writer, store *fakeRedisStore, args []string) {
	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "GET":
		val, ok := store.values[args[1]]
		if !ok {
			_, _ = conn.Write([]byte("$-1\r\n"))
		} else {
			_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(val), val)
		}
	case "SET":
		store.values[args[1]] = args[2]
		store.versions[args[1]]++
		delete(store.expires, args[1])
		if len(args) >= 5 {
			ttl, _ := strconv.Atoi(args[4])
			unit := time.Second
			if strings.EqualFold(args[3], "PX") {
				unit = time.Millisecond
			}
			store.expires[args[1]] = store.now + time.Duration(ttl)*unit
		}
		_, _ = conn.Write([]byte("+OK\r\n"))
	case "DEL":
		n := 0
		for _, k := range args[1:] {
			if _, ok := store.values[k]; ok {
				delete(store.values, k)
				delete(store.expires, k)
				store.versions[k]++
				n++
			}
		}
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

// Prime entries through the same guarded fill used by NodeQueries.
func (c *QueryDispatchCache) SetNoPendingQueries(ctx context.Context, nodeID uint) {
	_, _, _ = c.read(ctx, nodeID, func() (QueryReadQueries, bool, error) {
		return QueryReadQueries{}, false, nil
	})
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

func TestNodeQueries_InvalidationDuringEmptyLookup(t *testing.T) {
	for _, many := range []bool{false, true} {
		t.Run(fmt.Sprintf("many=%t", many), func(t *testing.T) {
			db := setupTestDB(t)
			q := setupQueries(t, db)
			q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 0)
			node := nodes.OsqueryNode{ID: 1}
			invalidated := false
			require.NoError(t, db.Callback().Row().After("gorm:row").Register("test:invalidate", func(tx *gorm.DB) {
				invalidated = true
				if many {
					q.Cache.InvalidateMany(context.Background(), []uint{node.ID})
				} else {
					q.Cache.Invalidate(context.Background(), node.ID)
				}
			}))

			result, _, err := q.NodeQueries(node)
			require.NoError(t, err)
			require.Empty(t, result)
			require.True(t, invalidated, "invalidation must occur between SQL lookup and cache refill")
			cached, err := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
			require.NoError(t, err)
			require.False(t, cached, "empty refill must not overwrite concurrent invalidation")
		})
	}
}

func TestNodeQueries_SQLFailureIsNotCached(t *testing.T) {
	db := setupTestDB(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 0)
	require.NoError(t, db.Migrator().DropTable(&NodeQuery{}))
	for range 2 {
		_, _, err := q.NodeQueries(nodes.OsqueryNode{ID: 1})
		require.Error(t, err)
		cached, err := q.Cache.HasNoPendingQueries(context.Background(), 1)
		require.NoError(t, err)
		require.False(t, cached)
	}
}

func TestQueryDispatchCache_DefaultAndConfiguredTTL(t *testing.T) {
	require.Equal(t, 2*time.Minute, NewQueryDispatchCache(nil, 0).ttl)
	require.Equal(t, 30*time.Second, NewQueryDispatchCache(nil, 30*time.Second).ttl)
}

func TestNodeQueries_CacheSurvivesPollAndExpires(t *testing.T) {
	for _, ttl := range []time.Duration{0, 3 * time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			db := setupTestDB(t)
			q := setupQueries(t, db)
			client, store := newFakeRedis(t)
			q.Cache = NewQueryDispatchCache(client, ttl)
			node := nodes.OsqueryNode{ID: 1}
			reads := 0
			require.NoError(t, db.Callback().Row().After("gorm:row").Register("test:count", func(tx *gorm.DB) { reads++ }))
			_, _, err := q.NodeQueries(node)
			require.NoError(t, err)
			store.mu.Lock()
			store.now = time.Minute
			store.mu.Unlock()
			_, _, err = q.NodeQueries(node)
			require.NoError(t, err)
			require.Equal(t, 1, reads, "60s poll should reuse the empty cache")
			store.mu.Lock()
			store.now = q.Cache.ttl
			store.mu.Unlock()
			_, _, err = q.NodeQueries(node)
			require.NoError(t, err)
			require.Equal(t, 2, reads, "expiry should force a fresh SQL lookup")
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Regression: console and file-explorer managers must invalidate the
// query-dispatch cache after creating a NodeQuery, so the next QueryRead
// hits the DB and picks up the new pending query. Without invalidation the
// 5s "no pending queries" cache entry hides the command from the node,
// causing frequent timeouts.
// ──────────────────────────────────────────────────────────────────────────────

func setupTestDBWithEnvs(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&DistributedQuery{}, &NodeQuery{}, &DistributedQueryTarget{}))
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	return db
}

func TestConsoleSubmitCommand_InvalidatesQueryDispatchCache(t *testing.T) {
	db := setupTestDBWithEnvs(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	// Create a node and prime the cache with "no queries pending."
	node := nodes.OsqueryNode{UUID: "node-uuid", NodeKey: "key", Hostname: "host", EnvironmentID: 1}
	require.NoError(t, db.Create(&node).Error)
	q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	cached, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.True(t, cached, "cache should be primed")

	// Simulate the console manager creating a hidden query + node_query row
	// directly (mirrors pkg/console/manager.go SubmitCommandWithTimeout).
	dq := DistributedQuery{
		Name: GenQueryName(), Query: "SELECT 1", Type: ConsoleQueryType,
		EnvironmentID: 1, Active: true, Hidden: true, Expected: 1,
	}
	require.NoError(t, db.Create(&dq).Error)
	require.NoError(t, db.Create(&NodeQuery{NodeID: node.ID, QueryID: dq.ID, Status: DistributedQueryStatusPending}).Error)

	// The console manager now calls Cache.Invalidate after the transaction.
	q.Cache.Invalidate(context.Background(), node.ID)

	cached, err := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.NoError(t, err)
	assert.False(t, cached, "cache should be invalidated after console command creation")

	// The next NodeQueries call should hit the DB and find the query.
	result, accelerate, err := q.NodeQueries(node)
	require.NoError(t, err)
	assert.Contains(t, result, dq.Name)
	assert.True(t, accelerate, "console query type should trigger acceleration")
}

func TestConsolePrimingCommand_InvalidatesQueryDispatchCache(t *testing.T) {
	db := setupTestDBWithEnvs(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	node := nodes.OsqueryNode{UUID: "node-uuid", NodeKey: "key", Hostname: "host", EnvironmentID: 1}
	require.NoError(t, db.Create(&node).Error)
	q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	require.True(t, func() bool { c, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID); return c }())

	// Simulate SubmitPrimingCommand creating a hidden query + node_query.
	dq := DistributedQuery{
		Name: GenQueryName(), Query: "SELECT 1", Type: ConsoleQueryType,
		EnvironmentID: 1, Active: true, Hidden: true, Expected: 1,
	}
	require.NoError(t, db.Create(&dq).Error)
	require.NoError(t, db.Create(&NodeQuery{NodeID: node.ID, QueryID: dq.ID, Status: DistributedQueryStatusPending}).Error)

	q.Cache.Invalidate(context.Background(), node.ID)

	cached, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	assert.False(t, cached, "cache should be invalidated after priming command creation")
}

func TestFileExplorerRequest_InvalidatesQueryDispatchCache(t *testing.T) {
	db := setupTestDBWithEnvs(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	node := nodes.OsqueryNode{UUID: "node-uuid", NodeKey: "key", Hostname: "host", EnvironmentID: 1}
	require.NoError(t, db.Create(&node).Error)
	q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	require.True(t, func() bool { c, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID); return c }())

	// Simulate the file explorer manager creating a hidden query + node_query
	// row directly (mirrors pkg/fileexplorer/manager.go submitRequest).
	dq := DistributedQuery{
		Name: GenQueryName(), Query: "SELECT 1", Type: FileExplorerQueryType,
		EnvironmentID: 1, Active: true, Hidden: true, Expected: 1,
	}
	require.NoError(t, db.Create(&dq).Error)
	require.NoError(t, db.Create(&NodeQuery{NodeID: node.ID, QueryID: dq.ID, Status: DistributedQueryStatusPending}).Error)

	q.Cache.Invalidate(context.Background(), node.ID)

	cached, err := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	require.NoError(t, err)
	assert.False(t, cached, "cache should be invalidated after file explorer request creation")

	result, accelerate, err := q.NodeQueries(node)
	require.NoError(t, err)
	assert.Contains(t, result, dq.Name)
	assert.True(t, accelerate, "file explorer query type should trigger acceleration")
}

func TestFileExplorerPrimingRequest_InvalidatesQueryDispatchCache(t *testing.T) {
	db := setupTestDBWithEnvs(t)
	q := setupQueries(t, db)
	q.Cache = NewQueryDispatchCache(newFakeRedisClient(t), 10*time.Second)

	node := nodes.OsqueryNode{UUID: "node-uuid", NodeKey: "key", Hostname: "host", EnvironmentID: 1}
	require.NoError(t, db.Create(&node).Error)
	q.Cache.SetNoPendingQueries(context.Background(), node.ID)
	require.True(t, func() bool { c, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID); return c }())

	dq := DistributedQuery{
		Name: GenQueryName(), Query: "SELECT 1", Type: FileExplorerQueryType,
		EnvironmentID: 1, Active: true, Hidden: true, Expected: 1,
	}
	require.NoError(t, db.Create(&dq).Error)
	require.NoError(t, db.Create(&NodeQuery{NodeID: node.ID, QueryID: dq.ID, Status: DistributedQueryStatusPending}).Error)

	q.Cache.Invalidate(context.Background(), node.ID)

	cached, _ := q.Cache.HasNoPendingQueries(context.Background(), node.ID)
	assert.False(t, cached, "cache should be invalidated after priming request creation")
}
