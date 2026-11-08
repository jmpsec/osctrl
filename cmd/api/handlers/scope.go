package handlers

import (
	"context"

	"github.com/jmpsec/osctrl/pkg/environments"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/users"
)

// actionScope is the targeting scope for QueryLevel or CarveLevel.
func (h *HandlersApi) actionScope(ctx context.Context, user, envUUID string, level users.AccessLevel) (handlers.NodeScope, error) {
	s := handlers.NodeScope{Tier: h.Users.TierContext(ctx, user, envUUID, level)}
	if s.Tier == users.TierTags {
		ids, err := h.Users.ScopeTagIDsContext(ctx, user, envUUID)
		if err != nil {
			return handlers.NodeScope{}, err
		}
		s.TagIDs = ids
	}
	return s, nil
}

// visibleScope is the nodes a user may list (paged list) and read logs for:
// the widest of their query tier, carve tier, and standard for plain user level.
func (h *HandlersApi) visibleScope(ctx context.Context, user, envUUID string) (handlers.NodeScope, error) {
	return h.readScope(ctx, user, envUUID, h.Users.CheckPermissionsContext(ctx, user, users.UserLevel, envUUID))
}

// dataScope is the nodes whose details, posture, query results and carved
// files a user may read: the widest of their query and carve tier, at least
// standard for the read-only admin role. Plain user level grants nothing.
func (h *HandlersApi) dataScope(ctx context.Context, user, envUUID string) (handlers.NodeScope, error) {
	return h.readScope(ctx, user, envUUID, h.Users.HasRoleContext(ctx, user, users.RoleReadOnly))
}

func (h *HandlersApi) readScope(ctx context.Context, user, envUUID string, standard bool) (handlers.NodeScope, error) {
	t := max(h.Users.TierContext(ctx, user, envUUID, users.QueryLevel), h.Users.TierContext(ctx, user, envUUID, users.CarveLevel))
	if standard {
		t = max(t, users.TierStandard)
	}
	s := handlers.NodeScope{Tier: t}
	if t == users.TierTags {
		ids, err := h.Users.ScopeTagIDsContext(ctx, user, envUUID)
		if err != nil {
			return handlers.NodeScope{}, err
		}
		s.TagIDs = ids
	}
	return s, nil
}

// resultScope is the dataScope for reading a query's results: the lowest tier across env
// and every environment the query targets, since its results mix nodes of all of them.
// An unresolvable target environment counts as no access. Tags come from env's scope.
func (h *HandlersApi) resultScope(ctx context.Context, user string, env environments.TLSEnvironment, queryName string) (handlers.NodeScope, error) {
	s, err := h.dataScope(ctx, user, env.UUID)
	if err != nil {
		return handlers.NodeScope{}, err
	}
	targets, err := h.Queries.GetTargets(queryName)
	if err != nil {
		return handlers.NodeScope{}, err
	}
	for _, t := range targets {
		if t.Type != nodes.EnvironmentSelector {
			continue
		}
		e, err := h.Envs.GetByUUID(t.Value)
		if err != nil {
			e, err = h.Envs.GetByName(t.Value)
		}
		if err != nil {
			s.Tier = users.TierNone
			continue
		}
		ts, err := h.dataScope(ctx, user, e.UUID)
		if err != nil {
			return handlers.NodeScope{}, err
		}
		s.Tier = min(s.Tier, ts.Tier)
	}
	return s, nil
}

// canReadQueries gates query and carve reads: the level itself, or the global
// read-only admin role. Run gates never use it.
func (h *HandlersApi) canReadQueries(ctx context.Context, user, envUUID string, level users.AccessLevel) bool {
	return h.Users.CheckPermissionsContext(ctx, user, level, envUUID) || h.Users.HasRoleContext(ctx, user, users.RoleReadOnly)
}

// visibleCarveFiles drops carved files from nodes outside scope (a dataScope).
func (h *HandlersApi) visibleCarveFiles(scope handlers.NodeScope, files []carves.CarvedFile) ([]carves.CarvedFile, error) {
	if scope.Tier == users.TierFull {
		return files, nil
	}
	ids := make([]uint, 0, len(files))
	for _, f := range files {
		ids = append(ids, f.NodeID)
	}
	if scope.Tier == users.TierStandard {
		// Files of hard-deleted nodes stay visible unless the node was sensitive.
		sens, err := scope.SensitiveIDs(h.DB, ids)
		if err != nil {
			return nil, err
		}
		out := make([]carves.CarvedFile, 0, len(files))
		for _, f := range files {
			if !sens[f.NodeID] {
				out = append(out, f)
			}
		}
		return out, nil
	}
	ok, err := scope.FilterIDs(h.DB, ids)
	if err != nil {
		return nil, err
	}
	in := make(map[uint]bool, len(ok))
	for _, id := range ok {
		in[id] = true
	}
	out := make([]carves.CarvedFile, 0, len(files))
	for _, f := range files {
		if in[f.NodeID] {
			out = append(out, f)
		}
	}
	return out, nil
}

// scopedTargetValue hides explicit node targets (uuid/host) a caller may not see: all of
// them below standard, and at standard unless they name a live, non-sensitive node of env.
// shortcut: targets naming deleted or unknown nodes are hidden below full tier.
// shortcut: blanks every uuid/host value below standard, even in-scope ones.
func (h *HandlersApi) scopedTargetValue(scope handlers.NodeScope, env environments.TLSEnvironment, typ, value string) string {
	if typ != "uuid" && typ != "host" || scope.Tier == users.TierFull {
		return value
	}
	if scope.Tier < users.TierStandard {
		return ""
	}
	n, err := h.Nodes.GetByIdentifierEnv(value, env.ID)
	if err != nil {
		return ""
	}
	sens, err := scope.SensitiveIDs(h.DB, []uint{n.ID})
	if err != nil || sens[n.ID] {
		return ""
	}
	return value
}
