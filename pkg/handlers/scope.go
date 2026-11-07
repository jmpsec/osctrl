package handlers

import (
	"github.com/jmpsec/osctrl/pkg/users"
	"gorm.io/gorm"
)

// NodeScope is the one filter restricting nodes to what a user may target or see.
type NodeScope struct {
	Tier   users.Tier
	TagIDs []uint
}

// Apply restricts a query over osquery_nodes to the scope.
func (s NodeScope) Apply(db *gorm.DB) *gorm.DB {
	switch s.Tier {
	case users.TierStandard, users.TierFull:
		// Part 3 excludes sensitive nodes for TierStandard here.
		return db
	case users.TierTags:
		if len(s.TagIDs) > 0 {
			// Tag deletes leave tagged_nodes rows behind, so the tag itself must be live.
			return db.Where("osquery_nodes.id IN (SELECT node_id FROM tagged_nodes WHERE admin_tag_id IN ? AND deleted_at IS NULL AND admin_tag_id IN (SELECT id FROM admin_tags WHERE deleted_at IS NULL))", s.TagIDs)
		}
	}
	return db.Where("1 = 0")
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

// UUIDs returns node UUIDs in the env (by name) inside the scope; nil means no filter.
func (s NodeScope) UUIDs(db *gorm.DB, envName string) ([]string, error) {
	if s.Tier >= users.TierStandard {
		return nil, nil
	}
	out := []string{}
	err := s.Apply(db.Table("osquery_nodes").Where("osquery_nodes.deleted_at IS NULL AND osquery_nodes.environment = ?", envName)).Pluck("osquery_nodes.uuid", &out).Error
	return out, err
}
