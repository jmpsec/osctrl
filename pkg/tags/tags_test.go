package tags

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGetTagsByNodeIDsReturnsTagsGroupedByNode(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:tags_by_node_ids?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	m := CreateTagManager(db)
	nodeA := nodes.OsqueryNode{ID: 10, EnvironmentID: 7}
	nodeB := nodes.OsqueryNode{ID: 11, EnvironmentID: 7}
	if err := m.TagNode("prod", nodeA, "alice", false, TagTypeTag, ""); err != nil {
		t.Fatalf("tag node a prod: %v", err)
	}
	if err := m.TagNode("critical", nodeA, "alice", false, TagTypeTag, ""); err != nil {
		t.Fatalf("tag node a critical: %v", err)
	}
	if err := m.TagNode("staging", nodeB, "alice", false, TagTypeTag, ""); err != nil {
		t.Fatalf("tag node b staging: %v", err)
	}

	got, err := m.GetTagsByNodeIDs([]uint{nodeA.ID, nodeB.ID})
	if err != nil {
		t.Fatalf("get tags by node ids: %v", err)
	}

	if len(got[nodeA.ID]) != 2 {
		t.Fatalf("expected two tags for node a, got %+v", got[nodeA.ID])
	}
	if got[nodeA.ID][0].Name != "critical" || got[nodeA.ID][1].Name != "prod" {
		t.Fatalf("expected node a tags sorted by name, got %+v", got[nodeA.ID])
	}
	if len(got[nodeB.ID]) != 1 || got[nodeB.ID][0].Name != "staging" {
		t.Fatalf("expected staging for node b, got %+v", got[nodeB.ID])
	}
}
