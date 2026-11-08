package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// fakeActivity answers every UUID with an empty series and ranks n1 and n2 as erroring.
type fakeActivity struct{}

func (fakeActivity) ReadSeries(_ context.Context, _ string, uuids []string, _ time.Time, _ int) (map[string]activity.NodeTileSeries, error) {
	out := map[string]activity.NodeTileSeries{}
	for _, u := range uuids {
		out[u] = activity.NodeTileSeries{}
	}
	return out, nil
}

func (fakeActivity) ReadEnvSeries(context.Context, string, time.Time, int) (activity.EnvSeries, error) {
	return activity.EnvSeries{}, nil
}

func (fakeActivity) TopErrorNodes(context.Context, string, time.Time, int, int) ([]activity.NodeErrorCount, error) {
	return []activity.NodeErrorCount{{NodeUUID: "N2", Errors: 9}, {NodeUUID: "N1", Errors: 5}}, nil
}

// siblingSetup marks n2 sensitive and gives "plain" user level and "ro" the read-only admin role.
func siblingSetup(t *testing.T) tierFixture {
	t.Helper()
	f := setupTiers(t)
	f.h.Activity = fakeActivity{}
	require.NoError(t, f.h.DB.Create(&tags.AdminTag{ID: 20, Name: "secret", EnvironmentID: f.env.ID, Sensitive: true}).Error)
	require.NoError(t, f.h.DB.Create(&tags.TaggedNode{AdminTagID: 20, NodeID: f.n2.ID}).Error)
	require.NoError(t, f.h.DB.Model(&f.n2).Update("hostname", "secret-host").Error)
	f.user(t, "plain")
	require.NoError(t, f.h.Users.SetEnvLevel("plain", f.env.UUID, users.UserLevel, true))
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: "root", Admin: true}))
	return f
}

func (f tierFixture) getQ(fn http.HandlerFunc, user, query string, vars map[string]string) *httptest.ResponseRecorder {
	r := consoleRequest(http.MethodGet, "/x"+query, nil, user)
	for k, v := range vars {
		r.SetPathValue(k, v)
	}
	rr := httptest.NewRecorder()
	fn(rr, r)
	return rr
}

func jsonKeys(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &m))
	return m
}

func TestNodeActivitySensitive404(t *testing.T) {
	f := siblingSetup(t)
	for name, fn := range map[string]http.HandlerFunc{"activity": f.h.NodeActivityHandler, "tiles": f.h.NodeActivityTilesHandler} {
		v := func(uuid string) map[string]string { return map[string]string{"env": f.env.Name, "uuid": uuid} }
		sensitive := f.getQ(fn, "plain", "", v("N2"))
		missing := f.getQ(fn, "plain", "", v("NOPE"))
		require.Equal(t, http.StatusNotFound, sensitive.Code, name)
		require.Equal(t, missing.Code, sensitive.Code, name)
		require.Equal(t, missing.Body.String(), sensitive.Body.String(), name)
		require.Equal(t, http.StatusOK, f.getQ(fn, "plain", "", v("N1")).Code, name)
		require.Equal(t, http.StatusOK, f.getQ(fn, "root", "", v("N2")).Code, name)
	}
}

func TestNodeActivityBatchDropsSensitive(t *testing.T) {
	f := siblingSetup(t)
	vars := map[string]string{"env": f.env.Name}
	for name, fn := range map[string]http.HandlerFunc{"activity": f.h.NodeActivityBatchHandler, "tiles": f.h.NodeActivityTilesBatchHandler} {
		rr := f.getQ(fn, "plain", "?uuids=N1,N2", vars)
		require.Equal(t, http.StatusOK, rr.Code, name)
		got := jsonKeys(t, rr.Body.Bytes())
		require.Contains(t, got, "N1", name)
		require.NotContains(t, got, "N2", name)
		require.Len(t, jsonKeys(t, f.getQ(fn, "root", "?uuids=N1,N2", vars).Body.Bytes()), 2, name)
	}
}

func TestEnvErrorNodesSkipsSensitive(t *testing.T) {
	f := siblingSetup(t)
	list := func(user string) []string {
		rr := f.getQ(f.h.EnvErrorNodesHandler, user, "", map[string]string{"env": f.env.Name})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var rows []ErrorNodeRow
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &rows))
		var out []string
		for _, r := range rows {
			out = append(out, r.UUID)
		}
		return out
	}
	require.Equal(t, []string{"N1"}, list("plain"))
	require.Equal(t, []string{"N2", "N1"}, list("root"))
}

func TestLookupSkipsSensitiveForReadOnly(t *testing.T) {
	f := siblingSetup(t)
	lookup := func(user, id string) *httptest.ResponseRecorder {
		r := consoleRequest(http.MethodPost, "/lookup", mustJSON(t, types.ApiLookupRequest{Identifier: id}), user)
		rr := httptest.NewRecorder()
		f.h.LookupNodeHandler(rr, r)
		return rr
	}
	hidden, missing := lookup("ro", "secret-host"), lookup("ro", "no-such-host")
	require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
	require.Equal(t, missing.Code, hidden.Code)
	require.Equal(t, missing.Body.String(), hidden.Body.String())
	require.Equal(t, http.StatusOK, lookup("ro", "N1").Code)
	require.Equal(t, http.StatusOK, lookup("root", "secret-host").Code)
}

func stdSetup(t *testing.T) tierFixture {
	t.Helper()
	f := siblingSetup(t)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	return f
}

func TestStandardTierListsExcludeSensitive(t *testing.T) {
	f := stdSetup(t)
	vars := map[string]string{"env": f.env.Name}
	for name, fn := range map[string]http.HandlerFunc{"active": f.h.ActiveNodesHandler, "inactive": f.h.InactiveNodesHandler, "all": f.h.AllNodesHandler} {
		rr := f.nodeGet(fn, "std", vars)
		if rr.Code == http.StatusOK {
			require.NotContains(t, nodeUUIDs(t, rr.Body.Bytes()), "N2", name)
		}
		require.NotContains(t, rr.Body.String(), "secret-host", name)
	}
	require.Contains(t, nodeUUIDs(t, f.nodeGet(f.h.AllNodesHandler, "std", vars).Body.Bytes()), "N1")
}

func TestStandardTierSensitiveNode404(t *testing.T) {
	f := stdSetup(t)
	cases := map[string]struct {
		fn  http.HandlerFunc
		key string
	}{
		"detail": {f.h.NodeHandler, "node"}, "logs": {f.h.NodeLogsHandler, "uuid"},
		"posture": {f.h.NodePostureHandler, "uuid"}, "score": {f.h.NodePostureScoreHandler, "uuid"},
	}
	for name, c := range cases {
		v := func(id string) map[string]string {
			return map[string]string{"env": f.env.Name, c.key: id, "type": "status"}
		}
		hidden, missing := f.nodeGet(c.fn, "std", v("N2")), f.nodeGet(c.fn, "std", v("NOPE"))
		require.Equal(t, http.StatusNotFound, hidden.Code, name)
		require.Equal(t, missing.Body.String(), hidden.Body.String(), name)
	}
	require.Equal(t, http.StatusOK, f.nodeGet(f.h.NodeHandler, "std", map[string]string{"env": f.env.Name, "node": "N1"}).Code)
}

func TestQueryShowHidesSensitiveTargetAtStandard(t *testing.T) {
	f := stdSetup(t)
	require.NoError(t, f.h.DB.Create(&queries.DistributedQuery{Name: "q1", Type: queries.StandardQueryType, EnvironmentID: f.env.ID}).Error)
	require.NoError(t, f.h.Queries.CreateTarget("q1", "uuid", "N2"))
	require.NoError(t, f.h.Queries.CreateTarget("q1", "uuid", "N1"))
	show := func(user string) string {
		return f.nodeGet(f.h.QueryShowHandler, user, map[string]string{"env": f.env.Name, "name": "q1"}).Body.String()
	}
	std := show("std")
	require.NotContains(t, std, `"value":"N2"`)
	require.Contains(t, std, `"value":"N1"`)
	require.Contains(t, show("alice"), `"value":"N2"`)
}

func TestQueryShowHidesDeletedNodeTargetAtStandard(t *testing.T) {
	f := stdSetup(t)
	require.NoError(t, f.h.DB.Create(&queries.DistributedQuery{Name: "q1", Type: queries.StandardQueryType, EnvironmentID: f.env.ID}).Error)
	require.NoError(t, f.h.Queries.CreateTarget("q1", "uuid", "N2"))
	require.NoError(t, f.h.DB.Unscoped().Delete(&f.n2).Error)
	show := func(user string) string {
		return f.nodeGet(f.h.QueryShowHandler, user, map[string]string{"env": f.env.Name, "name": "q1"}).Body.String()
	}
	require.NotContains(t, show("std"), "N2")
	require.Contains(t, show("alice"), `"value":"N2"`)
}

func TestNodeActivityResolvesByUUIDOnly(t *testing.T) {
	f := siblingSetup(t)
	// n1's hostname equals n2's UUID; the stats routes must not resolve by hostname.
	require.NoError(t, f.h.DB.Model(&f.n1).Update("hostname", "NOPE-UUID").Error)
	for name, fn := range map[string]http.HandlerFunc{"activity": f.h.NodeActivityHandler, "tiles": f.h.NodeActivityTilesHandler} {
		rr := f.getQ(fn, "root", "", map[string]string{"env": f.env.Name, "uuid": "NOPE-UUID"})
		require.Equal(t, http.StatusNotFound, rr.Code, name)
	}
}
