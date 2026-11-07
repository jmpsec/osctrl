package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/rs/zerolog/log"
)

// errNodeOutOfScope means a node named explicitly is outside the caller's tier.
var errNodeOutOfScope = errors.New("node out of scope")

// scopeTargets drops the node ids outside the caller's tier in each node's own
// environment, keeping input order. A node named in data.UUIDs or data.Hosts
// that is dropped returns errNodeOutOfScope; other drops are silent.
func (h *HandlersApi) scopeTargets(ctx context.Context, user string, level users.AccessLevel, data handlers.ProcessingQuery, ids []uint) ([]uint, error) {
	// Resolve explicit entries the same way CreateQueryCarve does.
	var explicit []uint
	for _, u := range data.UUIDs {
		if u != "" {
			n, err := h.Nodes.GetByUUIDEnv(u, data.EnvID)
			if err != nil {
				return nil, err
			}
			explicit = append(explicit, n.ID)
		}
	}
	for _, host := range data.Hosts {
		if host != "" {
			n, err := h.Nodes.GetByIdentifierEnv(host, data.EnvID)
			if err != nil {
				return nil, err
			}
			explicit = append(explicit, n.ID)
		}
	}
	// Filter ids plus the explicit nodes, so an explicit node intersected away
	// by another target is still judged on its own scope.
	all := append(append([]uint{}, ids...), explicit...)
	allowed := map[uint]bool{}
	if len(all) > 0 {
		var rows []struct {
			ID          uint
			Environment string
		}
		if err := h.DB.Table("osquery_nodes").Select("id, environment").Where("deleted_at IS NULL AND id IN ?", all).Scan(&rows).Error; err != nil {
			return nil, err
		}
		byEnv := map[string][]uint{}
		for _, r := range rows {
			byEnv[r.Environment] = append(byEnv[r.Environment], r.ID)
		}
		for name, group := range byEnv {
			env, err := h.Envs.GetByName(name)
			if err != nil {
				// Fail closed: a node whose environment cannot be resolved is dropped.
				log.Err(err).Msgf("dropping %d target nodes in unresolved environment %q", len(group), name)
				continue
			}
			scope, err := h.actionScope(ctx, user, env.UUID, level)
			if err != nil {
				return nil, fmt.Errorf("error getting scope: %w", err)
			}
			kept, err := scope.FilterIDs(h.DB, group)
			if err != nil {
				return nil, err
			}
			for _, id := range kept {
				allowed[id] = true
			}
		}
	}
	for _, id := range explicit {
		if !allowed[id] {
			return nil, errNodeOutOfScope
		}
	}
	out := []uint{}
	for _, id := range ids {
		if allowed[id] {
			out = append(out, id)
		}
	}
	return out, nil
}
