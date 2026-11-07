package users

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetScopeTagsReplaces(t *testing.T) {
	m := roleTestManager(t)
	require.NoError(t, m.SetScopeTags("alice", "e1", "root", []uint{1, 2}))
	require.NoError(t, m.SetScopeTags("alice", "e1", "root", []uint{2, 3}))
	ids, err := m.ScopeTagIDsContext(context.Background(), "alice", "e1")
	require.NoError(t, err)
	require.Equal(t, []uint{2, 3}, ids)
}

func TestDeleteScopeTagsForTag(t *testing.T) {
	m := roleTestManager(t)
	require.NoError(t, m.SetScopeTags("alice", "e1", "root", []uint{5, 6}))
	require.NoError(t, m.SetScopeTags("bob", "e1", "root", []uint{5}))
	require.NoError(t, m.DeleteScopeTagsForTag(5))
	a, _ := m.ScopeTagIDsContext(context.Background(), "alice", "e1")
	b, _ := m.ScopeTagIDsContext(context.Background(), "bob", "e1")
	require.Equal(t, []uint{6}, a)
	require.Empty(t, b)
}

func TestDeleteAllPermissionsClearsScopeTags(t *testing.T) {
	m := roleTestManager(t)
	require.NoError(t, m.Create(AdminUser{Username: "alice"}))
	require.NoError(t, m.SetScopeTags("alice", "e1", "root", []uint{1}))
	require.NoError(t, m.SetScopeTags("alice", "e2", "root", []uint{2}))
	require.NoError(t, m.DeleteEnvPermissions("alice", "e1"))
	ids, _ := m.ScopeTagIDsContext(context.Background(), "alice", "e1")
	require.Empty(t, ids)
	require.NoError(t, m.DeleteAllPermissions("alice"))
	ids, _ = m.ScopeTagIDsContext(context.Background(), "alice", "e2")
	require.Empty(t, ids)
}
