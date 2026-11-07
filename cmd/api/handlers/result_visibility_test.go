package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// resultFixture adds one query "q1" and one carve "c1" with a row/file per node n1 and n2.
func resultFixture(t *testing.T) tierFixture {
	t.Helper()
	f := setupTiers(t)
	require.NoError(t, f.h.DB.AutoMigrate(&logging.OsqueryQueryData{}, &carves.CarvedFile{}))
	for _, name := range []string{"q1", "c1"} {
		typ := queries.StandardQueryType
		if name == "c1" {
			typ = queries.CarveQueryType
		}
		require.NoError(t, f.h.DB.Create(&queries.DistributedQuery{Name: name, Type: typ, EnvironmentID: f.env.ID}).Error)
	}
	for _, n := range []string{"N1", "N2"} {
		require.NoError(t, f.h.DB.Create(&logging.OsqueryQueryData{UUID: n, Environment: f.env.UUID, Name: "q1", Data: `{"k":"` + n + `"}`}).Error)
	}
	nodeIDs := map[string]uint{"N1": f.n1.ID, "N2": f.n2.ID}
	for n, id := range nodeIDs {
		require.NoError(t, f.h.DB.Create(&carves.CarvedFile{CarveID: "cf-" + n, SessionID: "s-" + n, QueryName: "c1", UUID: n, NodeID: id, EnvironmentID: f.env.ID, Environment: f.env.Name}).Error)
	}
	return f
}

func (f tierFixture) get(fn http.HandlerFunc, user, target string, vars map[string]string) *httptest.ResponseRecorder {
	r := consoleRequest(http.MethodGet, target, nil, user)
	vars["env"] = f.env.Name
	for k, v := range vars {
		r.SetPathValue(k, v)
	}
	rr := httptest.NewRecorder()
	fn(rr, r)
	return rr
}

func TestQueryResultsTagScoped(t *testing.T) {
	f := resultFixture(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	rr := f.get(f.h.QueryResultsHandler, "tagger", "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.QueryResultsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.TotalItems)
	require.Len(t, resp.Items, 1)
	require.Equal(t, "N1", resp.Items[0]["uuid"])

	rr = f.get(f.h.QueryResultsCSVHandler, "tagger", "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "N1")
	require.NotContains(t, rr.Body.String(), "N2")

	// Explicit node targets are hidden below standard, kept for full.
	require.NoError(t, f.h.Queries.CreateTarget("q1", "uuid", "N2"))
	rr = f.get(f.h.QueryShowHandler, "tagger", "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotContains(t, rr.Body.String(), "N2")
	require.Contains(t, f.get(f.h.QueryShowHandler, "alice", "/x", map[string]string{"name": "q1"}).Body.String(), `"value":"N2"`)

	// A full-tier caller (env admin) still sees both.
	rr = f.get(f.h.QueryResultsHandler, "alice", "/x", map[string]string{"name": "q1"})
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 2, resp.TotalItems)
}

func TestQueryReadsReadOnlyAdmin(t *testing.T) {
	f := resultFixture(t)
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	v := func() map[string]string { return map[string]string{"name": "q1", "target": "all"} }
	for name, fn := range map[string]http.HandlerFunc{
		"show": f.h.QueryShowHandler, "list": f.h.QueryListHandler, "results": f.h.QueryResultsHandler, "csv": f.h.QueryResultsCSVHandler,
	} {
		rr := f.get(fn, "ro", "/x", v())
		require.Equal(t, http.StatusOK, rr.Code, name+": "+rr.Body.String())
	}
	rr := f.get(f.h.QueryResultsHandler, "ro", "/x", v())
	var resp types.QueryResultsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 2, resp.TotalItems)
	rr = f.run(t, false, "ro", types.ApiDistributedQueryRequest{})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
}

func TestCarveReadsTagScoped(t *testing.T) {
	f := resultFixture(t)
	f.user(t, "carver")
	f.tier(t, "carver", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	rr := f.get(f.h.CarveShowHandler, "carver", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var detail types.CarveDetailResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	require.Len(t, detail.Files, 1)
	require.Equal(t, "s-N1", detail.Files[0].SessionID)

	rr = f.get(f.h.CarveListHandler, "carver", "/x", map[string]string{})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "c1")

	// n2's file: 404 by explicit session, same as a nonexistent session.
	hidden := f.get(f.h.CarveArchiveHandler, "carver", "/x?session=s-N2", map[string]string{"name": "c1"})
	missing := f.get(f.h.CarveArchiveHandler, "carver", "/x?session=nope", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
	require.Equal(t, missing.Body.String(), hidden.Body.String())

	// With only n2's file left, the carve looks like one with no files yet.
	require.NoError(t, f.h.DB.Delete(&carves.CarvedFile{}, "session_id = ?", "s-N1").Error)
	rr = f.get(f.h.CarveArchiveHandler, "carver", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), "no carved files yet")
}

func TestCarveReadsAfterNodeHardDelete(t *testing.T) {
	f := resultFixture(t)
	f.user(t, "carver")
	f.tier(t, "carver", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	require.NoError(t, f.h.DB.Unscoped().Delete(&f.n1).Error)
	require.NoError(t, f.h.DB.Unscoped().Delete(&f.n2).Error)

	rr := f.get(f.h.CarveShowHandler, "alice", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var detail types.CarveDetailResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	require.Len(t, detail.Files, 2)
	// Past the visibility check: the session resolves (any failure is archiving, not 404).
	rr = f.get(f.h.CarveArchiveHandler, "alice", "/x?session=s-N1", map[string]string{"name": "c1"})
	require.NotContains(t, rr.Body.String(), "not found")

	rr = f.get(f.h.CarveShowHandler, "carver", "/x", map[string]string{"name": "c1"})
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	require.Empty(t, detail.Files)
	rr = f.get(f.h.CarveArchiveHandler, "carver", "/x?session=s-N1", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, rr.Code)
}

// The case the review flagged: user level must not widen a tag-scoped grant
// for query results or carved files.
func TestResultsUserPlusTagTier(t *testing.T) {
	f := resultFixture(t)
	f.user(t, "tagger")
	require.NoError(t, f.h.Users.SetEnvLevel("tagger", f.env.UUID, users.UserLevel, true))
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	f.tier(t, "tagger", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	rr := f.get(f.h.QueryResultsHandler, "tagger", "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.QueryResultsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.TotalItems)
	require.Equal(t, "N1", resp.Items[0]["uuid"])
	rr = f.get(f.h.QueryResultsCSVHandler, "tagger", "/x", map[string]string{"name": "q1"})
	require.NotContains(t, rr.Body.String(), "N2")

	rr = f.get(f.h.CarveShowHandler, "tagger", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var detail types.CarveDetailResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	require.Len(t, detail.Files, 1)
	require.Equal(t, "s-N1", detail.Files[0].SessionID)
	hidden := f.get(f.h.CarveArchiveHandler, "tagger", "/x?session=s-N2", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
}
