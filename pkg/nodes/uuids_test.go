package nodes

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestUUIDsByEnv(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryNode{}))
	for _, n := range []OsqueryNode{
		{UUID: "A1", EnvironmentID: 1, Platform: "ubuntu"},
		{UUID: "A2", EnvironmentID: 1, Platform: ""},
		{UUID: "WIN", EnvironmentID: 1, Platform: "Windows"},
		{UUID: "GONE", EnvironmentID: 1, Platform: "darwin"},
		{UUID: "B1", EnvironmentID: 2, Platform: "ubuntu"},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	require.NoError(t, db.Where("uuid = ?", "GONE").Delete(&OsqueryNode{}).Error)
	got, err := (&NodeManager{DB: db}).UUIDsByEnv(1)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"A1", "A2"}, got)
}
