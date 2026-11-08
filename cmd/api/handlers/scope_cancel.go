package handlers

import (
	"context"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/users"
)

// cancelOutOfScope hard-deletes the pending node-queries on these nodes whose
// creator no longer has the node in scope (judged in the node's own environment,
// failing closed). DistributedQuery.Expected is left as is.
// shortcut: grant changes do not cancel pending work, results stay hidden at read time; add a call in the permissions handlers if pending work must stop on revoke.
func (h *HandlersApi) cancelOutOfScope(ctx context.Context, nodeIDs []uint) error {
	if len(nodeIDs) == 0 {
		return nil
	}
	var pending []queries.NodeQuery
	if err := h.DB.Where("node_id IN ? AND status = ?", nodeIDs, queries.DistributedQueryStatusPending).Find(&pending).Error; err != nil {
		return fmt.Errorf("pending node queries: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	qIDs := make([]uint, 0, len(pending))
	for _, p := range pending {
		qIDs = append(qIDs, p.QueryID)
	}
	var dqs []queries.DistributedQuery
	if err := h.DB.Where("id IN ?", qIDs).Find(&dqs).Error; err != nil {
		return fmt.Errorf("queries: %w", err)
	}
	byQuery := make(map[uint]queries.DistributedQuery, len(dqs))
	for _, q := range dqs {
		byQuery[q.ID] = q
	}
	var ns []nodes.OsqueryNode
	if err := h.DB.Unscoped().Where("id IN ?", nodeIDs).Find(&ns).Error; err != nil {
		return fmt.Errorf("nodes: %w", err)
	}
	nodeEnv := make(map[uint]string, len(ns))
	for _, n := range ns {
		nodeEnv[n.ID] = n.Environment
	}

	type key struct {
		creator, env string
		level        users.AccessLevel
	}
	// Per (creator, node env, level): the node ids still in scope.
	inScope := map[key]map[uint]bool{}
	allowed := func(creator, envName string, level users.AccessLevel, nodeID uint) bool {
		k := key{creator, envName, level}
		set, ok := inScope[k]
		if !ok {
			set = map[uint]bool{}
			inScope[k] = set
			env, err := h.Envs.GetByName(envName)
			if err != nil || !h.Users.Exists(creator) {
				return false
			}
			scope, err := h.actionScope(ctx, creator, env.UUID, level)
			if err != nil {
				return false
			}
			ids, err := scope.FilterIDs(h.DB, nodeIDs)
			if err != nil {
				return false
			}
			for _, id := range ids {
				set[id] = true
			}
		}
		return set[nodeID]
	}

	var cancel, affected []uint
	for _, p := range pending {
		q, ok := byQuery[p.QueryID]
		level := users.QueryLevel
		if ok && q.Type == queries.CarveQueryType {
			level = users.CarveLevel
		}
		if ok && allowed(q.Creator, nodeEnv[p.NodeID], level, p.NodeID) {
			continue
		}
		cancel = append(cancel, p.ID)
		affected = append(affected, p.NodeID)
	}
	if len(cancel) == 0 {
		return nil
	}
	if err := h.Queries.CancelNodeQueries(cancel); err != nil {
		return fmt.Errorf("cancel node queries: %w", err)
	}
	h.Queries.Cache.InvalidateMany(ctx, affected)
	return nil
}
