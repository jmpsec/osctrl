package nodes

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func TestUpdateMetadataByUUID(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	testUpdateMetadataByUUID(t, db)
}

// Optional real-engine checks; each uses and removes its own prefixed table.
func TestUpdateMetadataByUUIDExternalBackend(t *testing.T) {
	for _, backend := range []string{"POSTGRES", "MYSQL"} {
		t.Run(backend, func(t *testing.T) {
			dsn := os.Getenv("OSCTRL_TEST_" + backend + "_DSN")
			if dsn == "" {
				t.Skip("set OSCTRL_TEST_" + backend + "_DSN to test this engine")
			}
			dialect := postgres.Open(dsn)
			if backend == "MYSQL" {
				dialect = mysql.Open(dsn)
			}
			db, err := gorm.Open(dialect, &gorm.Config{NamingStrategy: schema.NamingStrategy{
				TablePrefix: fmt.Sprintf("metadata_%d_", time.Now().UnixNano()),
			}})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&OsqueryNode{})) })
			testUpdateMetadataByUUID(t, db)
		})
	}
}

func testUpdateMetadataByUUID(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	repo := NodeManager{DB: db}

	// The same UUID enrolled in two environments has a live row in each.
	rows := []OsqueryNode{
		{UUID: "NODE-A", EnvironmentID: 1, Hostname: "old-host", Username: "keep-me", BytesReceived: 100},
		{UUID: "NODE-A", EnvironmentID: 2, Hostname: "other-env", BytesReceived: 7},
		{UUID: "NODE-B", EnvironmentID: 1, Hostname: "unrelated", BytesReceived: 50},
	}
	require.NoError(t, db.Create(&rows).Error)

	var selects, updates int
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("count_metadata_selects", func(*gorm.DB) { selects++ }))
	require.NoError(t, db.Callback().Update().After("gorm:update").Register("count_metadata_updates", func(*gorm.DB) { updates++ }))

	// Lower-case UUID, as host identifiers can arrive; empty fields must not
	// blank out what is stored.
	require.NoError(t, repo.UpdateMetadataByUUID("node-a", 1, NodeMetadata{
		Hostname:       "new-host",
		ConfigHash:     "abc123",
		OsqueryVersion: "5.23.1",
		BytesReceived:  25,
	}))
	require.Equal(t, 0, selects, "the per-log-batch hot path must not read the node first")
	require.Equal(t, 1, updates, "metadata must be a single UPDATE")

	got := map[string]OsqueryNode{}
	var all []OsqueryNode
	require.NoError(t, db.Order("id").Find(&all).Error)
	for _, n := range all {
		got[fmt.Sprintf("%s/%d", n.UUID, n.EnvironmentID)] = n
	}
	target := got["NODE-A/1"]
	require.Equal(t, "new-host", target.Hostname)
	require.Equal(t, "abc123", target.ConfigHash)
	require.Equal(t, "5.23.1", target.OsqueryVersion)
	require.Equal(t, "keep-me", target.Username, "an empty field must leave the stored value alone")
	require.Equal(t, 125, target.BytesReceived)

	// Only the row of the authenticated environment is touched.
	require.Equal(t, "other-env", got["NODE-A/2"].Hostname, "same UUID in another environment must be untouched")
	require.Equal(t, 7, got["NODE-A/2"].BytesReceived)
	require.Equal(t, "unrelated", got["NODE-B/1"].Hostname)
	require.Equal(t, 50, got["NODE-B/1"].BytesReceived)

	// Unknown nodes still report not-found, as the read-first version did.
	err := repo.UpdateMetadataByUUID("NODE-MISSING", 1, NodeMetadata{BytesReceived: 1})
	require.Error(t, err)
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "got %v", err)
	err = repo.UpdateMetadataByUUID("NODE-A", 99, NodeMetadata{BytesReceived: 1})
	require.True(t, errors.Is(err, gorm.ErrRecordNotFound), "wrong environment must not match: got %v", err)
}

// Log batches from one node are processed in parallel goroutines. Reading
// bytes_received and writing back a sum lost increments whenever two
// overlapped; the SQL-side increment must account for every byte.
func TestUpdateMetadataByUUIDConcurrentBytes(t *testing.T) {
	dir := t.TempDir()
	// A file database so connections share state and SQLite serialises
	// writers for real, rather than one in-memory connection doing it all.
	db, err := gorm.Open(sqlite.Open(dir+"/nodes.db?_busy_timeout=5000"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	repo := NodeManager{DB: db}
	require.NoError(t, db.Create(&OsqueryNode{UUID: "NODE-A", EnvironmentID: 1}).Error)

	const writers, each = 8, 25
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range each {
				if err := repo.UpdateMetadataByUUID("NODE-A", 1, NodeMetadata{BytesReceived: 3}); err != nil {
					t.Errorf("update: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()

	var n OsqueryNode
	require.NoError(t, db.Where("uuid = ?", "NODE-A").First(&n).Error)
	require.Equal(t, writers*each*3, n.BytesReceived, "concurrent batches lost increments")
}

func TestUUIDsInEnvironment(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	repo := NodeManager{DB: db}

	rows := []OsqueryNode{
		{UUID: "IN-PROD", Environment: "prod"},
		{UUID: "IN-STAGING", Environment: "staging"},
		{UUID: "DELETED", Environment: "prod"},
		// Enrolled in both: membership must not depend on which row is first.
		{UUID: "BOTH", Environment: "staging"},
		{UUID: "BOTH", Environment: "prod"},
	}
	require.NoError(t, db.Create(&rows).Error)
	require.NoError(t, db.Delete(&rows[2]).Error)

	var selects int
	require.NoError(t, db.Callback().Query().After("gorm:query").Register("count_membership_selects", func(*gorm.DB) { selects++ }))

	got, err := repo.UUIDsInEnvironment([]string{"in-prod", "IN-STAGING", "DELETED", "BOTH", "UNKNOWN"}, "PROD")
	require.NoError(t, err)
	require.Equal(t, 1, selects, "membership for a whole page must be one query")
	require.Equal(t, map[string]struct{}{"IN-PROD": {}, "BOTH": {}}, got,
		"only live nodes enrolled in the environment, keyed by stored UUID")

	empty, err := repo.UUIDsInEnvironment(nil, "prod")
	require.NoError(t, err)
	require.Empty(t, empty)
	require.Equal(t, 1, selects, "an empty set must not query")
}
