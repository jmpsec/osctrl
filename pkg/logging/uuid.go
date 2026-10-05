package logging

import (
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// NodeLogUUID preserves the column type originally inferred from gorm:"index"
// without retaining that standalone index. A size tag alone would narrow
// PostgreSQL's existing text column; an untagged string would expand MySQL's
// varchar(191) to longtext. Both cause unwanted table rewrites on startup.
type NodeLogUUID string

func (NodeLogUUID) GormDataType() string { return "string" }

func (NodeLogUUID) GormDBDataType(db *gorm.DB, _ *schema.Field) string {
	if db.Name() == "mysql" {
		return "varchar(191)"
	}
	return "text"
}
