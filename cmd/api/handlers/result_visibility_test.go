package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
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
	require.Equal(t, []string{"N1"}, csvUUIDs(t, rr.Body.String()))

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
	require.Equal(t, []string{"N1"}, csvUUIDs(t, rr.Body.String()))

	rr = f.get(f.h.CarveShowHandler, "tagger", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var detail types.CarveDetailResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	require.Len(t, detail.Files, 1)
	require.Equal(t, "s-N1", detail.Files[0].SessionID)
	hidden := f.get(f.h.CarveArchiveHandler, "tagger", "/x?session=s-N2", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
}

// sensitiveN2 tags n2 with a sensitive tag and adds a standard-tier user "std".
func sensitiveN2(t *testing.T, f tierFixture) {
	t.Helper()
	require.NoError(t, f.h.DB.Create(&tags.AdminTag{ID: 11, Name: "secret", EnvironmentID: f.env.ID, Sensitive: true}).Error)
	require.NoError(t, f.h.DB.Create(&tags.TaggedNode{AdminTagID: 11, NodeID: f.n2.ID}).Error)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
}

func TestStandardResultsSkipSensitive(t *testing.T) {
	f := resultFixture(t)
	sensitiveN2(t, f)
	vars := func() map[string]string { return map[string]string{"name": "q1"} }
	var resp types.QueryResultsResponse
	rr := f.get(f.h.QueryResultsHandler, "std", "/x", vars())
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.TotalItems)
	require.Equal(t, "N1", resp.Items[0]["uuid"])
	rr = f.get(f.h.QueryResultsCSVHandler, "std", "/x", vars())
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, []string{"N1"}, csvUUIDs(t, rr.Body.String()))

	rr = f.get(f.h.QueryResultsHandler, "alice", "/x", vars())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 2, resp.TotalItems)
	require.ElementsMatch(t, []string{"N1", "N2"}, csvUUIDs(t, f.get(f.h.QueryResultsCSVHandler, "alice", "/x", vars()).Body.String()))
}

func carveFiles(t *testing.T, f tierFixture, user string) []string {
	t.Helper()
	rr := f.get(f.h.CarveShowHandler, user, "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var detail types.CarveDetailResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &detail))
	out := []string{}
	for _, cf := range detail.Files {
		out = append(out, cf.SessionID)
	}
	return out
}

func TestStandardCarvesSkipSensitive(t *testing.T) {
	f := resultFixture(t)
	sensitiveN2(t, f)
	require.Equal(t, []string{"s-N1"}, carveFiles(t, f, "std"))
	require.ElementsMatch(t, []string{"s-N1", "s-N2"}, carveFiles(t, f, "alice"))

	hidden := f.get(f.h.CarveArchiveHandler, "std", "/x?session=s-N2", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
	// With only n2's file left, the carve looks like one with no files yet.
	require.NoError(t, f.h.DB.Delete(&carves.CarvedFile{}, "session_id = ?", "s-N1").Error)
	rr := f.get(f.h.CarveArchiveHandler, "std", "/x", map[string]string{"name": "c1"})
	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), "no carved files yet")
	rr = f.get(f.h.CarveArchiveHandler, "alice", "/x?session=s-N2", map[string]string{"name": "c1"})
	require.NotEqual(t, http.StatusNotFound, rr.Code, rr.Body.String())
}

func TestStandardCarveFromDeletedSensitiveNode(t *testing.T) {
	f := resultFixture(t)
	sensitiveN2(t, f)
	require.NoError(t, f.h.DB.Unscoped().Delete(&f.n2).Error)
	require.Equal(t, []string{"s-N1"}, carveFiles(t, f, "std"))
}

func TestStandardResultsOfDeletedSensitiveNode(t *testing.T) {
	f := resultFixture(t)
	sensitiveN2(t, f)
	require.NoError(t, f.h.DB.AutoMigrate(&nodes.ArchiveOsqueryNode{}))
	require.NoError(t, f.h.Nodes.ArchiveDelete(f.n2))
	rr := f.get(f.h.QueryResultsHandler, "std", "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.QueryResultsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.EqualValues(t, 1, resp.TotalItems)
	require.Equal(t, "N1", resp.Items[0]["uuid"])
}

// csvUUIDs parses a results CSV body and returns its uuid column.
func csvUUIDs(t *testing.T, body string) []string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	col := slices.Index(rows[0], "uuid")
	require.GreaterOrEqual(t, col, 0, rows[0])
	out := []string{}
	for _, r := range rows[1:] {
		out = append(out, r[col])
	}
	return out
}

// resultUUIDs returns the uuids of q1's results through both the JSON and CSV handlers.
func resultUUIDs(t *testing.T, f tierFixture, user string) ([]string, []string) {
	t.Helper()
	rr := f.get(f.h.QueryResultsHandler, user, "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp types.QueryResultsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	js := []string{}
	for _, it := range resp.Items {
		js = append(js, it["uuid"].(string))
	}
	rr = f.get(f.h.QueryResultsCSVHandler, user, "/x", map[string]string{"name": "q1"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return js, csvUUIDs(t, rr.Body.String())
}

// crossEnvResults targets q1 (in env) at the other env too, with results from
// b1 and a sensitive b2 there.
func crossEnvResults(t *testing.T, f tierFixture) {
	t.Helper()
	require.NoError(t, f.h.Queries.CreateTarget("q1", nodes.EnvironmentSelector, f.other.Name))
	require.NoError(t, f.h.DB.Create(&tags.AdminTag{ID: 12, Name: "secret-b", EnvironmentID: f.other.ID, Sensitive: true}).Error)
	require.NoError(t, f.h.DB.Create(&tags.TaggedNode{AdminTagID: 12, NodeID: f.b2.ID}).Error)
	for _, n := range []string{"B1", "B2"} {
		require.NoError(t, f.h.DB.Create(&logging.OsqueryQueryData{UUID: n, Environment: f.env.UUID, Name: "q1", Data: `{"k":"` + n + `"}`}).Error)
	}
}

func TestCrossEnvResultsStandardBoth(t *testing.T) {
	f := resultFixture(t)
	crossEnvResults(t, f)
	f.user(t, "std2")
	for _, e := range []string{f.env.UUID, f.other.UUID} {
		f.tier(t, "std2", e, users.QueryLevel, users.TierStandard)
	}
	js, cs := resultUUIDs(t, f, "std2")
	require.ElementsMatch(t, []string{"N1", "N2", "B1"}, js)
	require.ElementsMatch(t, []string{"N1", "N2", "B1"}, cs)
}

func TestCrossEnvResultsFullHereStandardThere(t *testing.T) {
	f := resultFixture(t)
	crossEnvResults(t, f)
	f.user(t, "mixed")
	f.tier(t, "mixed", f.env.UUID, users.QueryLevel, users.TierFull)
	f.tier(t, "mixed", f.other.UUID, users.QueryLevel, users.TierStandard)
	js, cs := resultUUIDs(t, f, "mixed")
	require.ElementsMatch(t, []string{"N1", "N2", "B1"}, js)
	require.ElementsMatch(t, []string{"N1", "N2", "B1"}, cs)
}

func TestCrossEnvResultsNoAccessThere(t *testing.T) {
	f := resultFixture(t)
	crossEnvResults(t, f)
	f.user(t, "std1")
	f.tier(t, "std1", f.env.UUID, users.QueryLevel, users.TierStandard)
	js, cs := resultUUIDs(t, f, "std1")
	require.Empty(t, js)
	require.Empty(t, cs)
}
