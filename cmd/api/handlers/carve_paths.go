package handlers

import (
	"context"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/users"
)

// A carve with an empty (legacy) Path is hidden from sub-full users once the
// environment has any sensitive path: PathTouches fails closed.
//
// carvePathHider returns a predicate reporting whether a carve path is hidden
// from user in env. Full carve tier sees everything and never reads the list.
func (h *HandlersApi) carvePathHider(ctx context.Context, user string, env environments.TLSEnvironment) (func(string) bool, error) {
	prefixes, err := h.carvePathPrefixes(ctx, user, env)
	if err != nil {
		return nil, err
	}
	return pathHider(prefixes), nil
}

// carvePathPrefixes returns the sensitive prefixes hidden from user in env:
// nil when the user has full carve tier or the list is empty.
func (h *HandlersApi) carvePathPrefixes(ctx context.Context, user string, env environments.TLSEnvironment) ([]string, error) {
	if h.Users.TierContext(ctx, user, env.UUID, users.CarveLevel) == users.TierFull {
		return nil, nil
	}
	rows, err := h.Envs.SensitivePaths(env.ID)
	if err != nil {
		return nil, err
	}
	var prefixes []string
	for _, r := range rows {
		prefixes = append(prefixes, r.Path)
	}
	return prefixes, nil
}

// pathHider hides paths touching prefixes; an empty list hides nothing.
func pathHider(prefixes []string) func(string) bool {
	if len(prefixes) == 0 {
		return func(string) bool { return false }
	}
	return func(p string) bool { return environments.PathTouches(p, prefixes) }
}

// carvePathHidden is true when the caller's carve tier in env is below full
// and path touches the environment's sensitive list.
func (h *HandlersApi) carvePathHidden(ctx context.Context, user string, env environments.TLSEnvironment, path string) (bool, error) {
	hide, err := h.carvePathHider(ctx, user, env)
	if err != nil {
		return false, err
	}
	return hide(path), nil
}

// visiblePathQueries drops carve queries the hide predicate rejects; never returns nil.
func visiblePathQueries(hide func(string) bool, in []queries.DistributedQuery) []queries.DistributedQuery {
	out := make([]queries.DistributedQuery, 0, len(in))
	for _, q := range in {
		if !hide(q.Path) {
			out = append(out, q)
		}
	}
	return out
}

// visiblePathFiles drops carved files the preloaded hide predicate rejects.
func visiblePathFiles(hide func(string) bool, in []carves.CarvedFile) []carves.CarvedFile {
	out := make([]carves.CarvedFile, 0, len(in))
	for _, f := range in {
		if !hide(f.Path) {
			out = append(out, f)
		}
	}
	return out
}

// carveQueryDenied is true when q is a carve the caller may not read through
// the query routes: no carve access, or a path hidden at their carve tier.
func (h *HandlersApi) carveQueryDenied(ctx context.Context, user string, env environments.TLSEnvironment, q queries.DistributedQuery) (bool, error) {
	if q.Type != queries.CarveQueryType {
		return false, nil
	}
	if !h.canReadQueries(ctx, user, env.UUID, users.CarveLevel) {
		return true, nil
	}
	return h.carvePathHidden(ctx, user, env, q.Path)
}
