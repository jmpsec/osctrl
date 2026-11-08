package handlers

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
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
	require.NoError(t, db.AutoMigrate(&nodes.OsqueryNode{}, &nodes.ArchiveOsqueryNode{}, &tags.TaggedNode{}, &tags.AdminTag{}))
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
	f, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, f.Only)
	require.Empty(t, f.Except)
}

func TestNodeScopeTagsEmpty(t *testing.T) {
	db, ids, _ := scopeDB(t)
	s := NodeScope{Tier: users.TierTags}
	got, err := s.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Empty(t, got)
	f, err := s.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.NotNil(t, f.Only)
	require.Empty(t, f.Only)
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
		f, err := s.ResultFilter(db, "dev")
		require.NoError(t, err)
		require.Nil(t, f.Only)
		require.Empty(t, f.Except)
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

func sensitiveTag(t *testing.T, db *gorm.DB, nodeID uint) *tags.TaggedNode {
	t.Helper()
	require.NoError(t, db.Create(&tags.AdminTag{ID: 9, Name: "t9", Sensitive: true}).Error)
	tn := &tags.TaggedNode{AdminTagID: 9, NodeID: nodeID}
	require.NoError(t, db.Create(tn).Error)
	return tn
}

func TestStandardExcludesSensitive(t *testing.T) {
	db, ids, _ := scopeDB(t)
	sensitiveTag(t, db, ids[1])
	got, err := NodeScope{Tier: users.TierStandard}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, []uint{ids[0], ids[2]}, got)
	got, err = NodeScope{Tier: users.TierFull}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, ids, got)
}

func TestTagsExcludesSensitive(t *testing.T) {
	db, ids, _ := scopeDB(t)
	sensitiveTag(t, db, ids[0])
	// n2 also carries a granted, non-sensitive tag; it must stay visible.
	require.NoError(t, db.Create(&tags.TaggedNode{AdminTagID: 7, NodeID: ids[1]}).Error)
	got, err := NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, []uint{ids[1]}, got)
}

func TestResultFilter(t *testing.T) {
	db, ids, _ := scopeDB(t)
	f, err := NodeScope{Tier: users.TierFull}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Equal(t, logging.NodeFilter{}, f)
	f, err = NodeScope{Tier: users.TierStandard}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Nil(t, f.Only)
	require.Empty(t, f.Except)
	sensitiveTag(t, db, ids[1])
	f, err = NodeScope{Tier: users.TierStandard}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Nil(t, f.Only)
	require.Equal(t, []string{"u2"}, f.Except)
	f, err = NodeScope{Tier: users.TierTags, TagIDs: []uint{7}}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Equal(t, []string{"u1"}, f.Only)
}

func TestDeletedSensitiveTagStopsCounting(t *testing.T) {
	db, ids, _ := scopeDB(t)
	sensitiveTag(t, db, ids[1])
	require.NoError(t, db.Unscoped().Delete(&tags.AdminTag{}, 9).Error)
	got, err := NodeScope{Tier: users.TierStandard}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, ids, got)
}

func TestSoftDeletedTaggingNotSensitive(t *testing.T) {
	db, ids, _ := scopeDB(t)
	require.NoError(t, db.Delete(sensitiveTag(t, db, ids[1])).Error)
	got, err := NodeScope{Tier: users.TierStandard}.FilterIDs(db, ids)
	require.NoError(t, err)
	require.Equal(t, ids, got)
}

func TestSensitiveIDsIncludesDeletedNodes(t *testing.T) {
	db, ids, _ := scopeDB(t)
	sensitiveTag(t, db, ids[1])
	require.NoError(t, db.Unscoped().Delete(&nodes.OsqueryNode{}, ids[1]).Error)
	got, err := NodeScope{Tier: users.TierStandard}.SensitiveIDs(db, []uint{ids[1], ids[0]})
	require.NoError(t, err)
	require.Equal(t, map[uint]bool{ids[1]: true}, got)
	got, err = NodeScope{}.SensitiveIDs(db, nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestResultFilterKeepsArchivedSensitiveNode(t *testing.T) {
	db, ids, _ := scopeDB(t)
	sensitiveTag(t, db, ids[1])
	require.NoError(t, db.Create(&nodes.ArchiveOsqueryNode{UUID: "u2", Environment: "dev", EnvironmentID: 1, NodeID: ids[1]}).Error)
	// Archive rows of the sensitive node id are hidden in every env; an unrelated archived node is not.
	require.NoError(t, db.Create(&nodes.ArchiveOsqueryNode{UUID: "u9", Environment: "prod", EnvironmentID: 2, NodeID: ids[1]}).Error)
	require.NoError(t, db.Create(&nodes.ArchiveOsqueryNode{UUID: "u8", Environment: "dev", EnvironmentID: 1, NodeID: ids[0]}).Error)
	require.NoError(t, db.Unscoped().Delete(&nodes.OsqueryNode{}, ids[1]).Error)
	f, err := NodeScope{Tier: users.TierStandard}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"u2", "u9"}, f.Except)
}

func TestResultFilterSurvivesEnvRename(t *testing.T) {
	db, ids, _ := scopeDB(t)
	require.NoError(t, db.AutoMigrate(&environments.TLSEnvironment{}))
	env := environments.TLSEnvironment{Name: "dev", UUID: "env-dev"}
	require.NoError(t, db.Create(&env).Error)
	sensitiveTag(t, db, ids[1])
	var n2 nodes.OsqueryNode
	require.NoError(t, db.First(&n2, ids[1]).Error)
	n2.EnvironmentID = env.ID
	require.NoError(t, (&nodes.NodeManager{DB: db}).ArchiveDelete(n2))
	require.NoError(t, (&environments.EnvManager{DB: db}).UpdateFields(env, map[string]interface{}{"name": "dev2"}))
	f, err := NodeScope{Tier: users.TierStandard}.ResultFilter(db, "dev2")
	require.NoError(t, err)
	require.Equal(t, []string{"u2"}, f.Except)
}

func TestResultFilterStandardAllEnvs(t *testing.T) {
	db, _, _ := scopeDB(t)
	var u4 nodes.OsqueryNode
	require.NoError(t, db.Where("uuid = ?", "u4").First(&u4).Error)
	sensitiveTag(t, db, u4.ID)
	// u4 lives in prod; results read through dev (a query targeting prod) must still drop it.
	f, err := NodeScope{Tier: users.TierStandard}.ResultFilter(db, "dev")
	require.NoError(t, err)
	require.Equal(t, []string{"u4"}, f.Except)
}
