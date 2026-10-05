package dbutil_test

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
)

type widget struct {
	ID        uint
	Name      string
	Kind      string
	Code      string `gorm:"type:varchar(36)"`
	CreatedAt time.Time
}

func openSQLite(t *testing.T, cfg *gorm.Config) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), cfg)
	require.NoError(t, err)
	return db
}

func countExecs(t *testing.T, db *gorm.DB) *int {
	t.Helper()
	n := new(int)
	require.NoError(t, db.Callback().Raw().After("gorm:raw").Register("count_index_ddl_"+t.Name(), func(*gorm.DB) { *n++ }))
	return n
}

func TestEnsureIndexesCreatesMissingOnce(t *testing.T) {
	db := openSQLite(t, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&widget{}))
	idx := dbutil.Index{Model: &widget{}, Name: "idx_widgets_kind_created", Columns: []string{"kind", "created_at"}}

	require.NoError(t, dbutil.EnsureIndexes(db, idx))
	require.True(t, db.Migrator().HasIndex(&widget{}, idx.Name))

	execs := countExecs(t, db)
	require.NoError(t, dbutil.EnsureIndexes(db, idx))
	require.Zero(t, *execs, "an existing index must not be rebuilt on every startup")
}

func TestEnsureIndexesHonoursTablePrefix(t *testing.T) {
	db := openSQLite(t, &gorm.Config{NamingStrategy: schema.NamingStrategy{TablePrefix: "pfx_"}})
	require.NoError(t, db.AutoMigrate(&widget{}))
	idx := dbutil.Index{Model: &widget{}, Name: "idx_pfx_widgets_name", Columns: []string{"name"}}

	require.NoError(t, dbutil.EnsureIndexes(db, idx))
	require.True(t, db.Migrator().HasIndex(&widget{}, idx.Name))
	var table string
	require.NoError(t, db.Raw(`SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?`, idx.Name).Scan(&table).Error)
	require.Equal(t, "pfx_widgets", table)
}

// One bad index must not stop the others from being created.
func TestEnsureIndexesContinuesPastFailures(t *testing.T) {
	db := openSQLite(t, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&widget{}))

	err := dbutil.EnsureIndexes(db,
		dbutil.Index{Model: &widget{}, Name: "idx_widgets_missing", Columns: []string{"no_such_column"}},
		dbutil.Index{Model: &widget{}, Name: "idx_widgets_name", Columns: []string{"name"}},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "idx_widgets_missing")
	require.True(t, db.Migrator().HasIndex(&widget{}, "idx_widgets_name"))
}

func osctrlIndexes() []dbutil.Index {
	return slices.Concat(nodes.Indexes(), queries.Indexes(), auditlog.Indexes(),
		carves.Indexes(), tags.Indexes(), logging.Indexes())
}

func osctrlModels() []any {
	return []any{
		&nodes.OsqueryNode{}, &queries.DistributedQuery{}, &queries.NodeQuery{}, &auditlog.AuditLog{},
		&carves.CarvedFile{}, &tags.TaggedNode{},
		&logging.OsqueryStatusData{}, &logging.OsqueryResultData{}, &logging.OsqueryQueryData{},
	}
}

// Every index osctrl declares must build against the real models — this is
// where a misspelt column name would surface.
func TestOsctrlIndexesBuild(t *testing.T) {
	db := openSQLite(t, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(osctrlModels()...))

	require.NoError(t, dbutil.EnsureIndexes(db, osctrlIndexes()...))
	names := map[string]bool{}
	for _, idx := range osctrlIndexes() {
		require.Falsef(t, names[idx.Name], "index name %s declared twice", idx.Name)
		names[idx.Name] = true
		require.Truef(t, db.Migrator().HasIndex(idx.Model, idx.Name), "index %s missing", idx.Name)
	}
}

// Optional real-engine checks, each on its own prefixed tables.
func externalDB(t *testing.T, backend string) (*gorm.DB, string) {
	t.Helper()
	dsn := os.Getenv("OSCTRL_TEST_" + backend + "_DSN")
	if dsn == "" {
		t.Skip("set OSCTRL_TEST_" + backend + "_DSN to test this engine")
	}
	dialect := postgres.Open(dsn)
	if backend == "MYSQL" {
		dialect = mysql.Open(dsn)
	}
	prefix := fmt.Sprintf("idx_%d_", time.Now().UnixNano())
	db, err := gorm.Open(dialect, &gorm.Config{NamingStrategy: schema.NamingStrategy{TablePrefix: prefix}})
	require.NoError(t, err)
	return db, prefix
}

func TestOsctrlIndexesBuildExternalBackend(t *testing.T) {
	for _, backend := range []string{"POSTGRES", "MYSQL"} {
		t.Run(backend, func(t *testing.T) {
			db, prefix := externalDB(t, backend)
			models := osctrlModels()
			t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(models...)) })
			require.NoError(t, db.AutoMigrate(models...))
			// Index names are schema-wide on Postgres, so the shared names
			// would collide with any other copy of these tables there.
			indexes := osctrlIndexes()
			for i := range indexes {
				indexes[i].Name = prefix + indexes[i].Name
			}

			require.NoError(t, dbutil.EnsureIndexes(db, indexes...))
			for _, idx := range indexes {
				require.Truef(t, db.Migrator().HasIndex(idx.Model, idx.Name), "index %s missing", idx.Name)
			}
			require.NoError(t, dbutil.EnsureIndexes(db, indexes...), "a second run must be a no-op")
		})
	}
}

// MySQL can only index TEXT by prefix, and rejects a prefix on a short
// varchar: one index over both kinds proves the prefix goes on the TEXT column
// alone.
func TestEnsureIndexesMySQLTextPrefix(t *testing.T) {
	db, _ := externalDB(t, "MYSQL")
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&widget{})) })
	require.NoError(t, db.AutoMigrate(&widget{}))
	idx := dbutil.Index{Model: &widget{}, Name: "idx_widgets_name_code", Columns: []string{"name", "code"}}

	require.NoError(t, dbutil.EnsureIndexes(db, idx))
	require.True(t, db.Migrator().HasIndex(&widget{}, idx.Name))
}

// A concurrent build that fails leaves an invalid index Postgres keeps
// maintaining but never reads. A failed CREATE UNIQUE INDEX CONCURRENTLY over
// duplicate rows is the documented way to produce one.
func TestEnsureIndexesRebuildsInvalidPostgresIndex(t *testing.T) {
	db, prefix := externalDB(t, "POSTGRES")
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(&widget{})) })
	require.NoError(t, db.AutoMigrate(&widget{}))
	require.NoError(t, db.Create(&[]widget{{Name: "dup"}, {Name: "dup"}}).Error)

	name := prefix + "idx_widgets_name"
	table := prefix + "widgets"
	require.Error(t, db.Exec(fmt.Sprintf(`CREATE UNIQUE INDEX CONCURRENTLY %q ON %q (name)`, name, table)).Error)
	var valid bool
	require.NoError(t, db.Raw(`SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = ?`, name).Scan(&valid).Error)
	require.False(t, valid, "fixture: the failed build should have left an invalid index")

	require.NoError(t, dbutil.EnsureIndexes(db, dbutil.Index{Model: &widget{}, Name: name, Columns: []string{"name"}}))
	require.NoError(t, db.Raw(`SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = ?`, name).Scan(&valid).Error)
	require.True(t, valid, "the invalid index must have been rebuilt")
}
