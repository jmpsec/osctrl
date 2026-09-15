package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestConfigCheckinKeepsObservedIP(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "test", Configuration: "{}"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{NodeKey: "key", UUID: "NODE", EnvironmentID: env.ID, IPAddress: "192.0.2.1"}
	require.NoError(t, db.Create(&node).Error)
	writer := &batchWriter{events: make(chan lastSeenUpdate, 1)}
	h := CreateHandlersTLS(WithEnvCache(environments.NewEnvCache(*envs)), WithNodes(nodesRepo), WithWriteHandler(writer))
	req := httptest.NewRequest(http.MethodPost, "/"+env.UUID+"/config", bytes.NewBufferString(`{"node_key":"key"}`))
	req.SetPathValue("env", env.UUID)
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	h.ConfigHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, writer.events, 1)
	ev := <-writer.events
	require.Equal(t, node.IPAddress, ev.IP, "cached IP may be stale after a move away and back")
	require.False(t, ev.SeenAt.IsZero())
}

func TestMergeCheckinKeepsLatestObservation(t *testing.T) {
	now := time.Now()
	batch := make(map[uint]lastSeenUpdate)
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now, IP: "new"})
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now.Add(-time.Second), IP: "old"})
	require.Equal(t, "new", batch[1].IP)
	require.Equal(t, now, batch[1].SeenAt)
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now.Add(time.Second)})
	require.Empty(t, batch[1].IP, "do not give an older IP a newer observation timestamp")
	require.Equal(t, now.Add(time.Second), batch[1].SeenAt)
}

func TestMergeCheckinPreservesQueryReadMarker(t *testing.T) {
	now := time.Now()
	batch := make(map[uint]lastSeenUpdate)
	// A newer generic check-in must not drop the query-read marker.
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now, QueryRead: true})
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now.Add(time.Second), IP: "later"})
	require.True(t, batch[1].QueryRead)
	require.Equal(t, now.Add(time.Second), batch[1].SeenAt)
	// An older query read must not resurrect an older timestamp.
	mergeCheckin(batch, lastSeenUpdate{NodeID: 1, SeenAt: now.Add(-time.Second), QueryRead: true})
	require.True(t, batch[1].QueryRead)
	require.Equal(t, now.Add(time.Second), batch[1].SeenAt)
}

func TestBatchWriterStampsLastQueryRead(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// One connection: each ":memory:" connection is a separate database,
	// so the writer goroutine and the assertions must share one.
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
	require.NoError(t, db.Create(&nodes.OsqueryNode{ID: 1}).Error)
	writer := &batchWriter{events: make(chan lastSeenUpdate, 4), batchSize: 50,
		timeout: 10 * time.Millisecond, nodesRepo: nodes.NodeManager{DB: db}}
	done := make(chan struct{})
	go func() { defer close(done); writer.run() }()
	t.Cleanup(func() { close(writer.events); <-done })

	seen := time.Now().UTC()
	writer.addEvent(lastSeenUpdate{NodeID: 1, SeenAt: seen, QueryRead: true})
	require.Eventually(t, func() bool {
		var got nodes.OsqueryNode
		return db.First(&got, 1).Error == nil && got.LastQueryRead.Equal(seen)
	}, time.Second, 5*time.Millisecond)

	// A later generic check-in updates last_seen but leaves the recorded
	// query read timestamp alone.
	generic := seen.Add(2 * time.Second)
	writer.addEvent(lastSeenUpdate{NodeID: 1, SeenAt: generic, IP: "192.0.2.1"})
	require.Eventually(t, func() bool {
		var got nodes.OsqueryNode
		return db.First(&got, 1).Error == nil && got.LastSeen.Equal(generic)
	}, time.Second, 5*time.Millisecond)
	var got nodes.OsqueryNode
	require.NoError(t, db.First(&got, 1).Error)
	require.True(t, got.LastQueryRead.Equal(seen), "generic check-ins must not move last_query_read")
}

func TestQueryReadCheckinIsMarked(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "test"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{NodeKey: "key", UUID: "NODE", EnvironmentID: env.ID}
	require.NoError(t, db.Create(&node).Error)
	writer := &batchWriter{events: make(chan lastSeenUpdate, 1)}
	h := CreateHandlersTLS(WithEnvCache(environments.NewEnvCache(*envs)), WithNodes(nodesRepo),
		WithQueries(queries.CreateQueries(db)), WithWriteHandler(writer))
	req := httptest.NewRequest(http.MethodPost, "/"+env.UUID+"/read", bytes.NewBufferString(`{"node_key":"key"}`))
	req.SetPathValue("env", env.UUID)
	w := httptest.NewRecorder()
	h.QueryReadHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, writer.events, 1)
	ev := <-writer.events
	require.True(t, ev.QueryRead, "the query read check-in must stamp last_query_read")
	require.False(t, ev.SeenAt.IsZero())
}

func TestBatchWriterFlushes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		timeout time.Duration
	}{{"timeout", 50, 10 * time.Millisecond}, {"size", 1, time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			require.NoError(t, err)
			sqlDB, err := db.DB()
			require.NoError(t, err)
			sqlDB.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = sqlDB.Close() })
			require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}))
			node := nodes.OsqueryNode{ID: 1}
			require.NoError(t, db.Create(&node).Error)
			writer := &batchWriter{events: make(chan lastSeenUpdate, 1), batchSize: tc.size,
				timeout: tc.timeout, nodesRepo: nodes.NodeManager{DB: db}}
			done := make(chan struct{})
			go func() { defer close(done); writer.run() }()
			t.Cleanup(func() { close(writer.events); <-done })
			seen := time.Now().UTC()
			writer.addEvent(lastSeenUpdate{NodeID: 1, SeenAt: seen, IP: "192.0.2.1"})
			require.Eventually(t, func() bool {
				var got nodes.OsqueryNode
				return db.First(&got, 1).Error == nil && got.LastSeen.Equal(seen) && got.IPAddress == "192.0.2.1"
			}, time.Second, 5*time.Millisecond)
		})
	}
}
