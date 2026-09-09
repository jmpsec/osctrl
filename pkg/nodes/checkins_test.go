package nodes

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func TestUpdateCheckins(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	testUpdateCheckins(t, db)
}

// Optional real-engine checks; each uses and removes its own prefixed table.
func TestUpdateCheckinsExternalBackend(t *testing.T) {
	for _, backend := range []string{"POSTGRES", "MYSQL"} {
		t.Run(backend, func(t *testing.T) {
			dsn := os.Getenv("OSCTRL_TEST_" + backend + "_DSN")
			if dsn == "" {
				t.Skip("set OSCTRL_TEST_" + backend + "_DSN to test this engine")
			}
			var dialect gorm.Dialector = postgres.Open(dsn)
			if backend == "MYSQL" {
				dialect = mysql.Open(dsn)
			}
			db, err := gorm.Open(dialect, &gorm.Config{NamingStrategy: schema.NamingStrategy{
				TablePrefix: fmt.Sprintf("checkin_%d_", time.Now().UnixNano()),
			}})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&OsqueryNode{})) })
			testUpdateCheckins(t, db)
		})
	}
}

func testUpdateCheckins(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	repo := NodeManager{DB: db}
	now := time.Now().UTC().Truncate(time.Second)
	rows := []OsqueryNode{
		{ID: 1, LastSeen: now, IPAddress: "old"},
		{ID: 2, LastSeen: now, IPAddress: "keep"},
		{ID: 3, LastSeen: now, IPAddress: "deleted"},
	}
	require.NoError(t, db.Create(&rows).Error)
	require.NoError(t, db.Delete(&rows[2]).Error)
	writes := 0
	require.NoError(t, db.Callback().Update().After("gorm:update").Register("count_updates", func(*gorm.DB) { writes++ }))
	updates := map[uint]Checkin{
		1: {NodeID: 1, SeenAt: now.Add(time.Second), IP: "new'quoted"},
		2: {NodeID: 2, SeenAt: now.Add(2 * time.Second)},
		3: {NodeID: 3, SeenAt: now.Add(time.Second), IP: "must-not-change"},
		4: {NodeID: 4, SeenAt: now.Add(time.Second)},
	}
	require.NoError(t, repo.UpdateCheckins(updates))
	require.Equal(t, 1, writes, "one SQL update for the batch, not per node")
	var got []OsqueryNode
	require.NoError(t, db.Unscoped().Order("id").Find(&got).Error)
	require.Len(t, got, 3, "missing nodes must not be inserted")
	require.Equal(t, "new'quoted", got[0].IPAddress)
	require.True(t, got[0].LastSeen.Equal(updates[1].SeenAt))
	require.Equal(t, "keep", got[1].IPAddress)
	require.True(t, got[1].LastSeen.Equal(updates[2].SeenAt))
	require.Equal(t, "deleted", got[2].IPAddress)
	require.True(t, got[2].LastSeen.Equal(now))
	require.True(t, got[0].UpdatedAt.Equal(rows[0].UpdatedAt), "heartbeat must not change metadata timestamp")

	// A delayed replica must not move either timestamp or IP backwards.
	require.NoError(t, repo.UpdateCheckins(map[uint]Checkin{1: {NodeID: 1, SeenAt: now, IP: "stale"}}))
	var node OsqueryNode
	require.NoError(t, db.First(&node, 1).Error)
	require.Equal(t, "new'quoted", node.IPAddress)
	require.True(t, node.LastSeen.Equal(updates[1].SeenAt))

	// Database timestamp precision must not allow a delayed sub-millisecond
	// observation to overwrite the IP associated with a newer observation.
	newer := now.Add(3*time.Second + 123400*time.Microsecond)
	older := newer.Add(-100 * time.Microsecond)
	require.NoError(t, repo.UpdateCheckins(map[uint]Checkin{1: {NodeID: 1, SeenAt: newer, IP: "latest"}}))
	require.NoError(t, repo.UpdateCheckins(map[uint]Checkin{1: {NodeID: 1, SeenAt: older, IP: "out-of-order"}}))
	require.NoError(t, db.First(&node, 1).Error)
	require.Equal(t, "latest", node.IPAddress)
}

func TestUpdateCheckinsChunksAndErrors(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	repo := NodeManager{DB: db}
	updates := make(map[uint]Checkin)
	for id := uint(1); id <= 250; id++ {
		updates[id] = Checkin{NodeID: id, SeenAt: time.Now(), IP: "127.0.0.1"}
	}
	writes := 0
	require.NoError(t, db.Callback().Update().After("gorm:update").Register("count_updates", func(*gorm.DB) { writes++ }))
	require.NoError(t, repo.UpdateCheckins(updates))
	require.Equal(t, 3, writes, "bound statement size even when configured writer batches are large")
	require.NoError(t, repo.UpdateCheckins(nil))
	require.Equal(t, 3, writes)
	for _, invalid := range []map[uint]Checkin{
		{0: {SeenAt: time.Now()}},
		{1: {NodeID: 2, SeenAt: time.Now()}},
		{1: {NodeID: 1}},
	} {
		require.Error(t, repo.UpdateCheckins(invalid))
	}
	require.Equal(t, 3, writes, "invalid observations must fail before SQL")
	require.NoError(t, db.Migrator().DropTable(&OsqueryNode{}))
	require.Error(t, repo.UpdateCheckins(map[uint]Checkin{1: updates[1]}))
}
