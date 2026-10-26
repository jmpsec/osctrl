package users

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func lockoutManager(t *testing.T, admins []string, plain []string) *UserManager {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateUserManager(db)
	for _, n := range admins {
		require.NoError(t, m.Create(AdminUser{Username: n, Admin: true}))
	}
	for _, n := range plain {
		require.NoError(t, m.Create(AdminUser{Username: n}))
	}
	return m
}

func TestCheckLockout(t *testing.T) {
	demote := EnvAccess{User: true}
	cases := []struct {
		name          string
		admins, plain []string
		actor, target string
		access        EnvAccess
		want          error
	}{
		{"self super-admin", []string{"a", "b"}, nil, "a", "a", demote, ErrSelfDemote},
		{"self non-super-admin", []string{"a"}, []string{"bob"}, "bob", "bob", demote, nil},
		{"last super-admin by other", []string{"a"}, nil, "op", "a", demote, ErrLastSuperAdmin},
		{"two admins by other", []string{"a", "b"}, nil, "op", "a", demote, nil},
		{"admin access short-circuits", []string{"a"}, nil, "a", "a", EnvAccess{Admin: true}, nil},
		{"non super-admin target", []string{"a"}, []string{"bob"}, "op", "bob", demote, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := lockoutManager(t, c.admins, c.plain)
			err := m.CheckLockout(c.actor, c.target, c.access)
			if c.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, c.want)
		})
	}
}

func TestCheckLockoutCountError(t *testing.T) {
	m := lockoutManager(t, []string{"a"}, nil)
	// Fail only the CountAdmins query (the one that does not filter by username).
	require.NoError(t, m.DB.Callback().Query().After("gorm:query").Register("fail_count", func(d *gorm.DB) {
		if !strings.Contains(d.Statement.SQL.String(), "username") {
			_ = d.AddError(errors.New("boom"))
		}
	}))
	err := m.CheckLockout("op", "a", EnvAccess{})
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrLastSuperAdmin)
	require.NotErrorIs(t, err, ErrSelfDemote)
}

// IsSelfDemotion is what the API refuses unconditionally; CheckLockout (DB
// path) additionally requires the target to be a global super-admin.
func TestIsSelfDemotion(t *testing.T) {
	require.True(t, IsSelfDemotion("a", "a", EnvAccess{User: true}))
	require.False(t, IsSelfDemotion("a", "a", EnvAccess{Admin: true}))
	require.False(t, IsSelfDemotion("a", "b", EnvAccess{}))
}
