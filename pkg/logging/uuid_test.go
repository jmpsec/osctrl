package logging

import (
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type legacyLogUUID struct {
	gorm.Model
	UUID string `gorm:"index"`
}

func TestNodeLogUUIDPreservesColumnTypes(t *testing.T) {
	for _, dialect := range []string{"mysql", "postgres", "sqlite"} {
		t.Run(dialect, func(t *testing.T) {
			conn, _, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			var driver gorm.Dialector
			switch dialect {
			case "mysql":
				driver = mysql.New(mysql.Config{Conn: conn, SkipInitializeWithVersion: true})
			case "postgres":
				driver = postgres.New(postgres.Config{Conn: conn})
			default:
				driver = sqlite.Open(":memory:")
			}
			db, err := gorm.Open(driver, &gorm.Config{DisableAutomaticPing: true})
			require.NoError(t, err)
			legacy, err := schema.Parse(&legacyLogUUID{}, &sync.Map{}, schema.NamingStrategy{})
			require.NoError(t, err)
			before := db.Migrator().FullDataTypeOf(legacy.LookUpField("UUID"))
			for _, model := range []any{&OsqueryStatusData{}, &OsqueryResultData{}} {
				current, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
				require.NoError(t, err)
				require.Equal(t, before, db.Migrator().FullDataTypeOf(current.LookUpField("UUID")), "upgrade must not change the UUID SQL type")
			}
		})
	}
}

func TestLogUUIDIndexUpgradeAndRestart(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	for _, model := range []any{&OsqueryStatusData{}, &OsqueryResultData{}} {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(model))
		table := stmt.Schema.Table
		oldName := db.NamingStrategy.IndexName(table, "uuid")
		require.NoError(t, db.Table(table).AutoMigrate(&legacyLogUUID{}))
		// Legacy model's naming differs; create the historical production name.
		require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS "+oldName+" ON "+table+" (uuid)").Error)
		require.NoError(t, db.AutoMigrate(model))
		require.True(t, db.Migrator().HasIndex(model, oldName))
	}
	require.NoError(t, db.AutoMigrate(&OsqueryQueryData{}))
	require.NoError(t, dbutil.EnsureIndexes(db, Indexes()...))
	for _, model := range []any{&OsqueryStatusData{}, &OsqueryResultData{}} {
		stmt := &gorm.Statement{DB: db}
		require.NoError(t, stmt.Parse(model))
		oldName := db.NamingStrategy.IndexName(stmt.Schema.Table, "uuid")
		require.False(t, db.Migrator().HasIndex(model, oldName))
		require.NoError(t, db.AutoMigrate(model))
		require.False(t, db.Migrator().HasIndex(model, oldName), "restart must not recreate the redundant index")
	}
	require.True(t, db.Migrator().HasIndex(&OsqueryQueryData{}, "idx_osquery_query_data_uuid"), "query log UUID index is not covered by name/created_at")
}
