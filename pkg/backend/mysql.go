package backend

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// mysqlDialector gives untyped strings tagged uniqueIndex varchar(191), as the
// driver already does for index and unique. Otherwise they become longtext,
// which MySQL cannot index (Error 1170). Other databases keep text.
type mysqlDialector struct{ *mysql.Dialector }

func (d mysqlDialector) DataTypeOf(f *schema.Field) string {
	if f.DataType == schema.String && f.Size == 0 && f.TagSettings["UNIQUEINDEX"] != "" {
		return "varchar(191)"
	}
	return d.Dialector.DataTypeOf(f)
}

// Migrator routes AutoMigrate's column types through DataTypeOf above.
func (d mysqlDialector) Migrator(db *gorm.DB) gorm.Migrator {
	m := d.Dialector.Migrator(db).(mysql.Migrator)
	m.Migrator.Dialector = d
	return m
}

func openMySQL(dsn string) gorm.Dialector {
	return mysqlDialector{mysql.Open(dsn).(*mysql.Dialector)}
}
