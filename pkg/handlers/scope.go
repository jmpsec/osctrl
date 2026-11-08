package handlers

import (
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/users"
	"gorm.io/gorm"
)

// NodeScope is the one filter restricting nodes to what a user may target or see.
type NodeScope struct {
	Tier   users.Tier
	TagIDs []uint
}

// sensitiveNodes selects ids of nodes carrying a live sensitive tag. The IS NOT NULL keeps
// NOT IN safe (a NULL in the list would make it match nothing); tag deletes are hard and
// leave tagged_nodes rows behind, so the tag join must find a live tag.
const sensitiveNodes = "SELECT tn.node_id FROM tagged_nodes tn JOIN admin_tags t ON t.id = tn.admin_tag_id WHERE tn.node_id IS NOT NULL AND tn.deleted_at IS NULL AND t.deleted_at IS NULL AND t.sensitive = ?"

// Apply restricts a query over osquery_nodes to the scope.
func (s NodeScope) Apply(db *gorm.DB) *gorm.DB {
	switch s.Tier {
	case users.TierFull:
		return db
	case users.TierStandard:
		return db.Where("osquery_nodes.id NOT IN ("+sensitiveNodes+")", true)
	case users.TierTags:
		if len(s.TagIDs) > 0 {
			// Tag deletes leave tagged_nodes rows behind, so the tag itself must be live.
			return db.Where("osquery_nodes.id IN (SELECT node_id FROM tagged_nodes WHERE admin_tag_id IN ? AND deleted_at IS NULL AND admin_tag_id IN (SELECT id FROM admin_tags WHERE deleted_at IS NULL))", s.TagIDs).
				Where("osquery_nodes.id NOT IN ("+sensitiveNodes+")", true)
		}
	}
	return db.Where("1 = 0")
}

// SensitiveIDs returns which of ids are sensitive. It reads tagged_nodes directly, so
// nodes whose row was deleted still count.
func (s NodeScope) SensitiveIDs(db *gorm.DB, ids []uint) (map[uint]bool, error) {
	out := map[uint]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	var found []uint
	if err := db.Raw(sensitiveNodes+" AND tn.node_id IN ?", true, ids).Scan(&found).Error; err != nil {
		return nil, err
	}
	for _, id := range found {
		out[id] = true
	}
	return out, nil
}

// FilterIDs returns the ids inside the scope, in input order.
func (s NodeScope) FilterIDs(db *gorm.DB, ids []uint) ([]uint, error) {
	out := []uint{}
	if len(ids) == 0 {
		return out, nil
	}
	var found []uint
	if err := s.Apply(db.Table("osquery_nodes").Where("osquery_nodes.deleted_at IS NULL AND osquery_nodes.id IN ?", ids)).Pluck("osquery_nodes.id", &found).Error; err != nil {
		return nil, err
	}
	in := make(map[uint]bool, len(found))
	for _, id := range found {
		in[id] = true
	}
	for _, id := range ids {
		if in[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// ResultFilter is the node filter for reading query results in envName: full reads
// everything, standard drops sensitive nodes of every environment (a query may target
// other environments), tags/none keep only in-scope nodes of envName.
func (s NodeScope) ResultFilter(db *gorm.DB, envName string) (logging.NodeFilter, error) {
	out := []string{}
	switch s.Tier {
	case users.TierFull:
		return logging.NodeFilter{}, nil
	case users.TierStandard:
		// shortcut: nodes archived before node_id was recorded cannot be matched; their old results stay visible at standard if a tag is later marked sensitive.
		// Archived rows cover hard-deleted nodes, whose tagged_nodes rows remain.
		// A re-enrolled node reusing a deleted sensitive node's UUID stays hidden (over-hides, never under-hides).
		err := db.Raw("SELECT n.uuid FROM osquery_nodes n WHERE n.id IN ("+sensitiveNodes+") UNION SELECT a.uuid FROM archive_osquery_nodes a WHERE a.node_id IN ("+sensitiveNodes+")", true, true).Scan(&out).Error
		return logging.NodeFilter{Except: out}, err
	}
	err := s.Apply(db.Table("osquery_nodes").Where("osquery_nodes.deleted_at IS NULL AND osquery_nodes.environment = ?", envName)).Pluck("osquery_nodes.uuid", &out).Error
	return logging.NodeFilter{Only: out}, err
}
