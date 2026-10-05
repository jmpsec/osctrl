package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestPermissionSnapshotQueriesAndRevocation(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateUserManager(db)
	user := AdminUser{Username: "alice"}
	require.NoError(t, m.Create(user))
	for _, level := range []AccessLevel{QueryLevel, CarveLevel} {
		require.NoError(t, m.CreatePermission(UserPermission{Username: user.Username, Environment: "one", AccessType: int(level), AccessValue: true}))
	}
	queries := 0
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("count_permissions", func(*gorm.DB) { queries++ }))
	ctx := WithPermissionCache(context.Background())
	CacheAuthenticatedUser(ctx, user)
	require.True(t, m.CheckPermissionsContext(ctx, "alice", QueryLevel, "one"))
	require.True(t, m.CheckPermissionsContext(ctx, "alice", CarveLevel, "one"))
	require.False(t, m.CheckPermissionsContext(ctx, "alice", AdminLevel, "one"))
	require.Equal(t, 1, queries, "one permission query for every topic in the same environment")
	require.False(t, m.CheckPermissionsContext(ctx, "alice", QueryLevel, "two"))
	require.False(t, m.CheckPermissionsContext(ctx, "alice", QueryLevel, "two"))
	require.Equal(t, 2, queries, "denials are cached and environments stay isolated")
	require.False(t, m.CheckPermissionsContext(ctx, "missing", QueryLevel, "one"))
	// Simulate a CLI or another replica changing the database directly.
	require.NoError(t, db.Model(&UserPermission{}).Where("username = ?", "alice").Update("access_value", false).Error)
	fresh := WithPermissionCache(ctx)
	require.False(t, m.CheckPermissionsContext(fresh, "alice", QueryLevel, "one"))
	require.False(t, m.CheckPermissionsContext(fresh, "alice", CarveLevel, "one"))
	// Without middleware, checks remain authoritative too.
	require.False(t, m.CheckPermissionsContext(context.Background(), "alice", QueryLevel, "one"))
}

func TestPermissionSnapshotAdminDemotionAndDeletion(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateUserManager(db)
	user := AdminUser{Username: "admin", Admin: true}
	require.NoError(t, m.Create(user))
	ctx := WithPermissionCache(context.Background())
	require.True(t, m.CheckPermissionsContext(ctx, "admin", AdminLevel, NoEnvironment))
	require.NoError(t, db.Model(&AdminUser{}).Where("username = ?", "admin").Update("admin", false).Error)
	require.False(t, m.CheckPermissionsContext(WithPermissionCache(ctx), "admin", AdminLevel, NoEnvironment))
	require.NoError(t, db.Where("username = ?", "admin").Delete(&AdminUser{}).Error)
	require.False(t, m.CheckPermissionsContext(WithPermissionCache(ctx), "admin", UserLevel, NoEnvironment))
}
