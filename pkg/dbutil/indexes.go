package dbutil

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// mysqlTextPrefix is the prefix length MySQL indexes TEXT columns with: it can
// only index those by prefix. 191 utf8mb4 characters is the length GORM itself
// gives indexed strings, and stays within InnoDB's key size in composites.
const mysqlTextPrefix = 191

// Index is a secondary index created outside GORM's struct tags.
//
// Tags would be the usual way, but they are unsafe for string columns that
// were created without an index: GORM's MySQL driver types an untagged string
// as longtext and an indexed one as varchar(191), so tagging an existing
// column makes AutoMigrate issue an ALTER that rebuilds the table and fails,
// or truncates, on any value longer than 191 characters. Tags also cannot
// reach the timestamps of an embedded gorm.Model.
type Index struct {
	// Model is the GORM model of the table, which also supplies any table
	// prefix from the naming strategy.
	Model any
	// Name must be unique in the schema.
	Name string
	// Columns are database column names, in index order.
	Columns []string
}

// EnsureIndexes creates whichever of indexes do not exist yet, and is a no-op
// for the rest. It is safe to run from several processes at once: osctrl-api
// and osctrl-tls both run it at startup.
//
// On Postgres the build is CONCURRENTLY, so writers are never blocked however
// large the table is. A concurrent build that is interrupted — the process
// restarting mid-build, say — leaves an invalid index that Postgres keeps
// maintaining on every write but never reads; those are dropped and rebuilt,
// unless another session is still building them.
//
// MySQL builds secondary indexes online. SQLite holds its single write lock
// for the build, which is short on the databases it is used for.
func EnsureIndexes(db *gorm.DB, indexes ...Index) error {
	var errs []error
	for _, idx := range indexes {
		if err := ensureIndex(db, idx); err != nil {
			errs = append(errs, fmt.Errorf("index %s: %w", idx.Name, err))
		}
	}
	return errors.Join(errs...)
}

// BuildIndexes runs EnsureIndexes without holding up the caller: in the
// background on Postgres and MySQL, where a build can take minutes on a large
// table but does not block writers, and inline on SQLite, whose databases are
// small and which allows one writer at a time regardless. A failure is logged
// rather than returned — the indexes speed reads up; nothing depends on them
// existing — and the next startup tries again.
func BuildIndexes(db *gorm.DB, indexes ...Index) {
	run := func() {
		if err := EnsureIndexes(db, indexes...); err != nil {
			log.Warn().Err(err).Msg("creating database indexes")
		}
	}
	if db.Name() == "sqlite" {
		run()
		return
	}
	go run()
}

func ensureIndex(db *gorm.DB, idx Index) error {
	if !db.Migrator().HasIndex(idx.Model, idx.Name) {
		return createIndex(db, idx)
	}
	if db.Name() != "postgres" {
		return nil
	}
	var valid, building bool
	err := db.Raw(`SELECT i.indisvalid,
			EXISTS (SELECT 1 FROM pg_stat_progress_create_index p WHERE p.index_relid = c.oid)
		FROM pg_class c
		JOIN pg_index i ON i.indexrelid = c.oid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relname = ? AND n.nspname = current_schema()`, idx.Name).Row().Scan(&valid, &building)
	if err != nil {
		return fmt.Errorf("check validity: %w", err)
	}
	if valid || building {
		return nil
	}
	log.Warn().Str("index", idx.Name).Msg("rebuilding invalid index left by an interrupted concurrent build")
	if err := db.Exec("DROP INDEX CONCURRENTLY IF EXISTS " + quote(db, idx.Name)).Error; err != nil {
		return fmt.Errorf("drop invalid index: %w", err)
	}
	return createIndex(db, idx)
}

func createIndex(db *gorm.DB, idx Index) error {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(idx.Model); err != nil {
		return fmt.Errorf("parse model: %w", err)
	}
	textColumns, err := mysqlTextColumns(db, idx.Model)
	if err != nil {
		return err
	}
	columns := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		columns[i] = quote(db, c)
		if textColumns[c] {
			columns[i] += fmt.Sprintf("(%d)", mysqlTextPrefix)
		}
	}
	on := fmt.Sprintf("%s ON %s (%s)", quote(db, idx.Name), quote(db, stmt.Schema.Table), strings.Join(columns, ", "))
	var sql string
	switch db.Name() {
	case "postgres":
		sql = "CREATE INDEX CONCURRENTLY IF NOT EXISTS " + on
	case "mysql":
		// MySQL has no IF NOT EXISTS here; ensureIndex already checked.
		sql = "CREATE INDEX " + on
	default:
		sql = "CREATE INDEX IF NOT EXISTS " + on
	}
	return db.Exec(sql).Error
}

// mysqlTextColumns reports which columns of model are TEXT or BLOB on MySQL,
// the only ones that need a prefix length. A prefix on a short varchar is an
// error, so this reads the live column types instead of assuming them. Other
// dialects get an empty set.
func mysqlTextColumns(db *gorm.DB, model any) (map[string]bool, error) {
	if db.Name() != "mysql" {
		return nil, nil
	}
	types, err := db.Migrator().ColumnTypes(model)
	if err != nil {
		return nil, fmt.Errorf("read column types: %w", err)
	}
	text := make(map[string]bool)
	for _, t := range types {
		name := strings.ToLower(t.DatabaseTypeName())
		if strings.Contains(name, "text") || strings.Contains(name, "blob") {
			text[t.Name()] = true
		}
	}
	return text, nil
}

func quote(db *gorm.DB, name string) string {
	var b strings.Builder
	db.QuoteTo(&b, name)
	return b.String()
}
