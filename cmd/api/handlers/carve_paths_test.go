package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func (f tierFixture) sensitive(t *testing.T, env environments.TLSEnvironment, p string) {
	t.Helper()
	require.NoError(t, f.h.DB.AutoMigrate(&environments.SensitivePath{}))
	_, err := f.h.Envs.AddSensitivePath(env.ID, p, "test")
	require.NoError(t, err)
}

func (f tierFixture) carvePost(t *testing.T, user, path string, envs ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(types.ApiDistributedQueryRequest{Path: path, Environments: envs})
	require.NoError(t, err)
	r := consoleRequest(http.MethodPost, "/run", body, user)
	r.SetPathValue("env", f.env.Name)
	rr := httptest.NewRecorder()
	f.h.CarvesRunHandler(rr, r)
	return rr
}

func (f tierFixture) carveCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("type = ?", queries.CarveQueryType).Count(&n).Error)
	return n
}

func TestCarveRunSensitivePathRefused(t *testing.T) {
	f := setupTiers(t)
	f.sensitive(t, f.env, "/etc/shadow")
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	for _, p := range []string{"/etc/shadow", "/etc"} {
		rr := f.carvePost(t, "std", p)
		require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
		require.Contains(t, rr.Body.String(), "path is sensitive")
	}
	require.EqualValues(t, 0, f.carveCount(t))
	require.Equal(t, http.StatusCreated, f.carvePost(t, "std", "/etc/passwd").Code)
	require.Equal(t, http.StatusCreated, f.carvePost(t, "alice", "/etc/shadow").Code)
}

func TestCarveRunSensitivePathInTargetEnv(t *testing.T) {
	f := setupTiers(t)
	f.sensitive(t, f.other, "/etc/shadow")
	f.user(t, "x")
	f.tier(t, "x", f.env.UUID, users.CarveLevel, users.TierFull)
	f.tier(t, "x", f.other.UUID, users.CarveLevel, users.TierStandard)
	rr := f.carvePost(t, "x", "/etc/shadow", f.other.Name)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "path is sensitive")
	require.EqualValues(t, 0, f.carveCount(t))
}

// hiddenCarve: alice carved /etc/shadow before it became sensitive.
func hiddenCarve(t *testing.T, f tierFixture) {
	t.Helper()
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("name = ?", "c1").Update("path", "/etc/shadow").Error)
	require.NoError(t, f.h.DB.Model(&carves.CarvedFile{}).Where("query_name = ?", "c1").Update("path", "/etc/shadow").Error)
	f.sensitive(t, f.env, "/etc/shadow")
}

func assertCarveHidden(t *testing.T, f tierFixture, user string) {
	t.Helper()
	rr := f.get(f.h.CarveListHandler, user, "/x", map[string]string{})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotContains(t, rr.Body.String(), "c1")
	rr = f.get(f.h.CarveQueriesHandler, user, "/x", map[string]string{"target": "all"})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NotContains(t, rr.Body.String(), "c1")
	for _, fn := range []http.HandlerFunc{f.h.CarveShowHandler, f.h.CarveArchiveHandler} {
		hidden := f.get(fn, user, "/x", map[string]string{"name": "c1"})
		missing := f.get(fn, user, "/x", map[string]string{"name": "nope"})
		require.Equal(t, http.StatusNotFound, hidden.Code, hidden.Body.String())
		require.Equal(t, missing.Body.String(), hidden.Body.String())
	}
}

func TestCarveReadsHideSensitivePath(t *testing.T) {
	f := resultFixture(t)
	hiddenCarve(t, f)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	assertCarveHidden(t, f, "std")
	rr := f.get(f.h.CarveListHandler, "alice", "/x", map[string]string{})
	require.Contains(t, rr.Body.String(), "c1")
	require.Equal(t, http.StatusOK, f.get(f.h.CarveShowHandler, "alice", "/x", map[string]string{"name": "c1"}).Code)
	rr = f.get(f.h.CarveArchiveHandler, "alice", "/x?session=s-N1", map[string]string{"name": "c1"})
	require.NotEqual(t, http.StatusNotFound, rr.Code, rr.Body.String())
}

func TestCarveReadsDropHiddenFiles(t *testing.T) {
	f := resultFixture(t)
	f.sensitive(t, f.env, "/etc/shadow")
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("name = ?", "c1").Update("path", "/etc/hosts").Error)
	require.NoError(t, f.h.DB.Model(&carves.CarvedFile{}).Where("path = ''").Update("path", "/etc/hosts").Error)
	require.NoError(t, f.h.DB.Model(&carves.CarvedFile{}).Where("session_id = ?", "s-N2").Update("path", "/etc/shadow").Error)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	require.Equal(t, []string{"s-N1"}, carveFiles(t, f, "std"))
	require.ElementsMatch(t, []string{"s-N1", "s-N2"}, carveFiles(t, f, "alice"))
}

func TestCarveReadsCarveTierDecides(t *testing.T) {
	f := resultFixture(t)
	hiddenCarve(t, f)
	f.user(t, "q")
	f.tier(t, "q", f.env.UUID, users.QueryLevel, users.TierFull)
	f.tier(t, "q", f.env.UUID, users.CarveLevel, users.TierStandard)
	assertCarveHidden(t, f, "q")
}

func TestCarveReadsReadOnlyAdminHidden(t *testing.T) {
	f := resultFixture(t)
	hiddenCarve(t, f)
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: "ro", ReadOnlyAdmin: true}))
	assertCarveHidden(t, f, "ro")
}

func TestCarveTypeViaQueryRoutes(t *testing.T) {
	f := resultFixture(t)
	hiddenCarve(t, f)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	f.user(t, "qonly")
	f.tier(t, "qonly", f.env.UUID, users.QueryLevel, users.TierFull)
	routes := map[string]http.HandlerFunc{"show": f.h.QueryShowHandler, "results": f.h.QueryResultsHandler, "csv": f.h.QueryResultsCSVHandler}
	vars := func(n string) map[string]string { return map[string]string{"name": n, "target": "all"} }
	for name, fn := range routes {
		missing := f.get(fn, "std", "/x", vars("nope"))
		require.Equal(t, http.StatusNotFound, missing.Code, name)
		hidden := f.get(fn, "std", "/x", vars("c1"))
		require.Equal(t, http.StatusNotFound, hidden.Code, name+": "+hidden.Body.String())
		require.Equal(t, missing.Body.String(), hidden.Body.String(), name)
		require.Equal(t, http.StatusOK, f.get(fn, "alice", "/x", vars("c1")).Code, name)
		// Query-only user: no carve access at all, even for a non-sensitive carve path.
		require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("name = ?", "c1").Update("path", "/etc/hosts").Error)
		qo := f.get(fn, "qonly", "/x", vars("c1"))
		require.Equal(t, http.StatusNotFound, qo.Code, name+": "+qo.Body.String())
		require.Equal(t, missing.Body.String(), qo.Body.String(), name)
		require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("name = ?", "c1").Update("path", "/etc/shadow").Error)
	}
}

func TestCarveRunRejectsBadPath(t *testing.T) {
	f := setupTiers(t)
	for _, p := range []string{"etc/shadow", "/etc/../x", `\\?\C:\x`} {
		rr := f.carvePost(t, "alice", p)
		require.Equal(t, http.StatusBadRequest, rr.Code, p+": "+rr.Body.String())
	}
	require.EqualValues(t, 0, f.carveCount(t))
}

func TestCarveListSearchNoOracle(t *testing.T) {
	f := resultFixture(t)
	hiddenCarve(t, f)
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("name = ?", "c1").Update("query", carves.GenCarveQuery("/etc/shadow", false)).Error)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.CarveLevel, users.TierStandard)
	page := func(user, q string) types.CarvesPagedResponse {
		rr := f.get(f.h.CarveListHandler, user, "/x?q="+q, map[string]string{})
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var resp types.CarvesPagedResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		return resp
	}
	resp := page("std", "shad")
	require.EqualValues(t, 0, resp.TotalItems)
	require.Equal(t, 0, resp.TotalPages)
	require.Empty(t, resp.Items)
	require.EqualValues(t, 1, page("alice", "shad").TotalItems)
	// A page number that overflows (page-1)*pageSize must not panic.
	rr := f.get(f.h.CarveListHandler, "std", "/x?page=4611686018427387904&page_size=4", map[string]string{})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}
