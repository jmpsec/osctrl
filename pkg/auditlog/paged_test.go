package auditlog

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Actor is an exact ownership filter: "alice" must not see "alice-admin"
// rows, and "_" must not act as a LIKE wildcard over every actor.
func TestGetPagedActorIsExactMatch(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m, err := CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	for _, u := range []string{"alice", "alice-admin", "bob", "_"} {
		require.NoError(t, db.Create(&AuditLog{Username: u, LogType: LogTypeLogin}).Error)
	}
	for _, actor := range []string{"alice", "_"} {
		rows, total, err := m.GetPaged(PageFilter{Actor: actor})
		require.NoError(t, err)
		require.EqualValues(t, 1, total, actor)
		require.Equal(t, actor, rows[0].Username)
	}
}
