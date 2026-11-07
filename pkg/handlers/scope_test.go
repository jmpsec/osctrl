package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func scopeDB(t *testing.T) (*gorm.DB, []uint, *tags.TaggedNode) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}, &tags.TaggedNode{}, &tags.AdminTag{}))
	require.NoError(t, db.Create(&[]tags.AdminTag{{ID: 7, Name: "t7"}, {ID: 8, Name: "t8"}}).Error)
	ns := []nodes.OsqueryNode{
		{UUID: "u1", Environment: "dev"}, {UUID: "u2", Environment: "dev"},
		{UUID: "u3", Environment: "dev"}, {UUID: "u4", Environment: "prod"},
	}
	require.NoError(t, db.Create(&ns).Error)
	tn1 := &tags.TaggedNode{AdminTagID: 7, NodeID: ns[0].ID}
	require.NoError(t, db.Create(tn1).Error)
	require.NoError(t, db.Create(&tags.TaggedNode{AdminTagID: 8, NodeID: ns[1].ID}).Error)
	return db, []uint{ns[0].ID, ns[1].ID, ns[2].ID}, tn1
}

func TestNodeScopeTags(t *testing.T) {
	db, ids, _ := scopeDB(t)
	got, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, []uint{ids[0]}, got)
	// Input order is kept.
	got, err = NodeScope{Tier: users.TierTags, TagIDs: []uint{7, 8}}.FilterIDs(db, []uint{ids[1], ids[2], ids[0]})
	require.NoError(t, err)
	require.Equal(t, []uint{ids[1], ids[0]}, got)
	u, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.UUIDs(db, "dev")
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, u)
}

func TestNodeScopeTagsEmpty(t *testing.T) {
	db, ids, _ := scopeDB(t)
	s := NodeScope{Tier: users.TierTags}
	got, err := s.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Empty(t, got)
	u, err := s.UUIDs(db, "dev")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Empty(t, u)
}

func TestNodeScopeNone(t *testing.T) {
	db, ids, _ := scopeDB(t)
	got, err := NodeScope{Tier: users.TierNone}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Empty(t, got)
	got, err = NodeScope{Tier: users.TierNone}.FilterIDs(db, nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestNodeScopeStandardAndFull(t *testing.T) {
	db, ids, _ := scopeDB(t)
	for _, tier := range []users.Tier{users.TierStandard, users.TierFull} {
		s := NodeScope{Tier: tier}
		got, err := s.FilterIDs(db, ids)
		require.NoError(t, err)
		require.Equal(t, ids, got)
		u, err := s.UUIDs(db, "dev")
		require.NoError(t, err)
		require.Nil(t, u)
	}
}

func TestNodeScopeIgnoresSoftDeletedTagging(t *testing.T) {
	db, ids, tn1 := scopeDB(t)
	require.NoError(t, db.Delete(tn1).Error)
	got, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestNodeScopeIgnoresDeletedTag(t *testing.T) {
	db, ids, _ := scopeDB(t)
	// Hard delete, as DeleteGet does; tagged_nodes rows for tag 7 remain.
	require.NoError(t, db.Unscoped().Delete(&tags.AdminTag{}, 7).Error)
	got, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Empty(t, got)
}
