package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// nodeGet calls a node read handler as user with the given path values.
func (f tierFixture) nodeGet(fn http.HandlerFunc, user string, vars map[string]string) *httptest.ResponseRecorder {
	r := consoleRequest(http.MethodGet, "/x", nil, user)
	for k, v := range vars {
		r.SetPathValue(k, v)
	}
	rr := httptest.NewRecorder()
	fn(rr, r)
	return rr
}

func (f tierFixture) paged(t *testing.T, user string) types.NodesPagedResponse {
	t.Helper()
	rr := f.nodeGet(f.h.NodesPagedHandler, user, map[string]string{"env": f.env.Name})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.NodesPagedResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	return resp
}

func nodeUUIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var ns []nodes.OsqueryNode
	require.NoError(t, json.Unmarshal(body, &ns))
	var out []string
	for _, n := range ns {
		out = append(out, n.UUID)
	}
	return out
}

func TestNodeListsForTagScopedUser(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	vars := map[string]string{"env": f.env.Name}
	for name, fn := range map[string]http.HandlerFunc{"active": f.h.ActiveNodesHandler, "all": f.h.AllNodesHandler} {
		rr := f.nodeGet(fn, "tagger", vars)
		require.Equal(t, http.StatusOK, rr.Code, name+rr.Body.String())
		require.Equal(t, []string{"N1"}, nodeUUIDs(t, rr.Body.Bytes()), name)
	}
	p := f.paged(t, "tagger")
	require.Equal(t, int64(1), p.TotalItems)
	require.Len(t, p.Items, 1)
	require.Equal(t, "N1", p.Items[0].UUID)
}

func TestNodeDetailOutOfScope404(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	n2 := f.nodeGet(f.h.NodeHandler, "tagger", map[string]string{"env": f.env.Name, "node": "N2"})
	require.Equal(t, http.StatusNotFound, n2.Code, n2.Body.String())
	missing := f.nodeGet(f.h.NodeHandler, "tagger", map[string]string{"env": f.env.Name, "node": "NOPE"})
	require.Equal(t, http.StatusNotFound, missing.Code)
	require.Equal(t, missing.Body.String(), n2.Body.String())
	require.Equal(t, http.StatusOK, f.nodeGet(f.h.NodeHandler, "tagger", map[string]string{"env": f.env.Name, "node": "N1"}).Code)

	v := map[string]string{"env": f.env.Name, "uuid": "N2", "type": "status"}
	require.Equal(t, http.StatusNotFound, f.nodeGet(f.h.NodeLogsHandler, "tagger", v).Code)
	require.Equal(t, http.StatusNotFound, f.nodeGet(f.h.NodePostureHandler, "tagger", v).Code)
	require.Equal(t, http.StatusNotFound, f.nodeGet(f.h.NodePostureScoreHandler, "tagger", v).Code)
}

func TestNodeListsForUserLevel(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "plain")
	require.NoError(t, f.h.Users.SetEnvLevel("plain", f.env.UUID, users.UserLevel, true))
	// User level alone sees the paged list and node logs...
	require.Equal(t, int64(3), f.paged(t, "plain").TotalItems)
	logs := f.nodeGet(f.h.NodeLogsHandler, "plain", map[string]string{"env": f.env.Name, "uuid": "N2", "type": "status"})
	require.NotEqual(t, http.StatusForbidden, logs.Code, logs.Body.String())
	require.NotEqual(t, http.StatusNotFound, logs.Code, logs.Body.String())
	// ...but no node data: lists, detail and posture need a query or carve tier.
	vars := map[string]string{"env": f.env.Name}
	for name, fn := range map[string]http.HandlerFunc{"active": f.h.ActiveNodesHandler, "inactive": f.h.InactiveNodesHandler, "all": f.h.AllNodesHandler} {
		require.Equal(t, http.StatusForbidden, f.nodeGet(fn, "plain", vars).Code, name)
	}
	require.Equal(t, http.StatusForbidden, f.nodeGet(f.h.NodeHandler, "plain", map[string]string{"env": f.env.Name, "node": "N1"}).Code)
	v := map[string]string{"env": f.env.Name, "uuid": "N1"}
	require.Equal(t, http.StatusForbidden, f.nodeGet(f.h.NodePostureHandler, "plain", v).Code)
	require.Equal(t, http.StatusForbidden, f.nodeGet(f.h.NodePostureScoreHandler, "plain", v).Code)
}

// User level does not widen a tag-scoped query grant for node data.
func TestNodeDataUserPlusTagTier(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	require.NoError(t, f.h.Users.SetEnvLevel("tagger", f.env.UUID, users.UserLevel, true))
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	rr := f.nodeGet(f.h.AllNodesHandler, "tagger", map[string]string{"env": f.env.Name})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, []string{"N1"}, nodeUUIDs(t, rr.Body.Bytes()))
	require.Equal(t, http.StatusNotFound, f.nodeGet(f.h.NodeHandler, "tagger", map[string]string{"env": f.env.Name, "node": "N2"}).Code)
	// The paged list follows user level.
	require.Equal(t, int64(3), f.paged(t, "tagger").TotalItems)
}

func TestNodeListsNoAccess403(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "nobody")
	vars := map[string]string{"env": f.env.Name}
	for _, fn := range []http.HandlerFunc{f.h.ActiveNodesHandler, f.h.InactiveNodesHandler, f.h.AllNodesHandler, f.h.NodesPagedHandler} {
		require.Equal(t, http.StatusForbidden, f.nodeGet(fn, "nobody", vars).Code)
	}
	require.Equal(t, http.StatusForbidden, f.nodeGet(f.h.NodeHandler, "nobody", map[string]string{"env": f.env.Name, "node": "N1"}).Code)
}

func TestNodeListsReadOnlyAdmin(t *testing.T) {
	f := setupTiers(t)
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	p := f.paged(t, "ro")
	require.Equal(t, int64(3), p.TotalItems)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	require.NotContains(t, strings.ToLower(string(raw)), "secret")
	rr := f.nodeGet(f.h.AllNodesHandler, "ro", map[string]string{"env": f.env.Name})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Len(t, nodeUUIDs(t, rr.Body.Bytes()), 3)
	require.Equal(t, http.StatusOK, f.nodeGet(f.h.NodeHandler, "ro", map[string]string{"env": f.env.Name, "node": "N2"}).Code)
	// Past the gate; the nil posture manager answers 503.
	require.Equal(t, http.StatusServiceUnavailable, f.nodeGet(f.h.NodePostureHandler, "ro", map[string]string{"env": f.env.Name, "uuid": "N2"}).Code)
}

func TestReadOnlyAdminEnvironments(t *testing.T) {
	h := setupReadOnlyRoles(t)
	rr := roReq(h, "ro", http.MethodGet, "/x", "", nil, h.EnvironmentsHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var list []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &list))
	require.Len(t, list, 2)
	for _, e := range list {
		for _, k := range []string{"secret", "certificate", "flags"} {
			require.NotContains(t, e, k)
		}
	}
	rr = roReq(h, "ro", http.MethodGet, "/x", "", map[string]string{"env": "uuid-dev"}, h.EnvironmentHandler)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var one map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &one))
	for _, k := range []string{"secret", "certificate", "flags"} {
		require.NotContains(t, one, k)
	}
}

func TestNodeDetailHidesNodeKeyFromNonAdmin(t *testing.T) {
	f := setupTiers(t)
	require.NoError(t, f.h.DB.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "N1").Update("node_key", "k3y").Error)
	f.user(t, "plain")
	f.tier(t, "plain", f.env.UUID, users.QueryLevel, users.TierStandard)
	vars := map[string]string{"env": f.env.Name, "node": "N1"}
	rr := f.nodeGet(f.h.NodeHandler, "plain", vars)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotContains(t, rr.Body.String(), "k3y")
	f.user(t, "adm")
	require.NoError(t, f.h.Users.SetEnvLevel("adm", f.env.UUID, users.AdminLevel, true))
	require.Contains(t, f.nodeGet(f.h.NodeHandler, "adm", vars).Body.String(), "k3y")
}
