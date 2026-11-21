package santa

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// testDB opens an empty database for one test. By default it is SQLite in
// memory. With OSCTRL_TEST_SANTA_ENGINE set to POSTGRES or MYSQL it is a new
// schema (PostgreSQL) or database (MySQL) on the server at
// OSCTRL_TEST_<ENGINE>_DSN, dropped when the test ends, so the whole package
// runs on that engine. The models name their tables, so a table prefix
// cannot keep tests apart.
func testDB(t *testing.T, sqliteDSN string) *gorm.DB {
	t.Helper()
	engine := os.Getenv("OSCTRL_TEST_SANTA_ENGINE")
	if engine == "" {
		db, err := gorm.Open(sqlite.Open(sqliteDSN), &gorm.Config{})
		require.NoError(t, err)
		return db
	}
	dsn := os.Getenv("OSCTRL_TEST_" + engine + "_DSN")
	require.NotEmpty(t, dsn, "OSCTRL_TEST_SANTA_ENGINE=%s needs OSCTRL_TEST_%s_DSN", engine, engine)
	name := fmt.Sprintf("santa_t%d", time.Now().UnixNano())
	var admin, db *gorm.DB
	var err error
	switch engine {
	case "POSTGRES":
		admin, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("CREATE SCHEMA "+name).Error)
		sep := " "
		if strings.Contains(dsn, "://") {
			sep = "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
		}
		db, err = gorm.Open(postgres.Open(dsn+sep+"search_path="+name), &gorm.Config{})
		require.NoError(t, err)
		t.Cleanup(func() { dropAndClose(t, admin, "DROP SCHEMA "+name+" CASCADE") })
	case "MYSQL":
		admin, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
		cfg, err := mysqldriver.ParseDSN(dsn)
		require.NoError(t, err)
		cfg.DBName = name
		// The sql_mode osctrl-api and osctrl-tls connect with.
		cfg.Params = map[string]string{"sql_mode": "'" + backend.MySQLSQLMode + "'"}
		cfg.ParseTime = true
		db, err = gorm.Open(mysql.Open(cfg.FormatDSN()), &gorm.Config{})
		require.NoError(t, err)
		t.Cleanup(func() { dropAndClose(t, admin, "DROP DATABASE "+name) })
	default:
		t.Fatalf("OSCTRL_TEST_SANTA_ENGINE must be POSTGRES or MYSQL, not %q", engine)
	}
	// Close before the drop above, which runs after this (cleanups are LIFO).
	t.Cleanup(func() { closeDB(db) })
	return db
}

func dropAndClose(t *testing.T, admin *gorm.DB, drop string) {
	require.NoError(t, admin.Exec(drop).Error)
	closeDB(admin)
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
