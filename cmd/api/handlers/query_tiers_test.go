package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

// tierFixture: env "env" holds n1 (tagged 7) and n2 (untagged); env "other"
// holds b1 (tagged 9) and b2.
type tierFixture struct {
	h              *HandlersApi
	env            environments.TLSEnvironment
	other          environments.TLSEnvironment
	n1, n2, b1, b2 nodes.OsqueryNode
}

func setupTiers(t *testing.T) tierFixture {
	t.Helper()
	db, h, env, _ := setupConsoleHandlers(t)
	h.DebugHTTPConfig = &config.YAMLConfigurationDebug{}
	auditLog, err := auditlog.CreateAuditLogManager(db, "api", false)
	require.NoError(t, err)
	h.AuditLog = auditLog
	require.NoError(t, db.AutoMigrate(&tags.TaggedNode{}, &tags.AdminTag{}, &users.UserScopeTag{}))
	require.NoError(t, db.Create(&[]tags.AdminTag{{ID: 7, Name: "t7", EnvironmentID: env.ID}, {ID: 9, Name: "t9"}}).Error)
	other := environments.TLSEnvironment{UUID: "other-uuid", Name: "other"}
	require.NoError(t, db.Create(&other).Error)
	mk := func(uuid string, e environments.TLSEnvironment) nodes.OsqueryNode {
		n := nodes.OsqueryNode{UUID: uuid, Platform: "linux", EnvironmentID: e.ID, Environment: e.Name, LastSeen: time.Now()}
		require.NoError(t, db.Create(&n).Error)
		return n
	}
	f := tierFixture{h: h, env: env, other: other, n1: mk("N1", env), n2: mk("N2", env), b1: mk("B1", other), b2: mk("B2", other)}
	require.NoError(t, db.Create(&tags.TaggedNode{AdminTagID: 7, NodeID: f.n1.ID}).Error)
	require.NoError(t, db.Create(&tags.TaggedNode{AdminTagID: 9, NodeID: f.b1.ID}).Error)
	return f
}

func (f tierFixture) user(t *testing.T, name string) {
	t.Helper()
	require.NoError(t, f.h.Users.Create(users.AdminUser{Username: name}))
}

func (f tierFixture) tier(t *testing.T, user, envUUID string, level users.AccessLevel, tier users.Tier, tagIDs ...uint) {
	t.Helper()
	require.NoError(t, f.h.Users.SetEnvTier(user, envUUID, level, tier))
	if tier == users.TierTags {
		require.NoError(t, f.h.Users.SetScopeTags(user, envUUID, "root", tagIDs))
	}
}

func (f tierFixture) run(t *testing.T, carve bool, user string, req types.ApiDistributedQueryRequest) *httptest.ResponseRecorder {
	t.Helper()
	if req.Query == "" {
		req.Query = "select 1;"
	}
	req.Path = "/etc/hosts"
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := consoleRequest(http.MethodPost, "/run", body, user)
	r.SetPathValue("env", f.env.Name)
	rr := httptest.NewRecorder()
	if carve {
		f.h.CarvesRunHandler(rr, r)
	} else {
		f.h.QueriesRunHandler(rr, r)
	}
	return rr
}

// targeted returns the node ids holding a node-query for the created query and its Expected.
func (f tierFixture) targeted(t *testing.T, rr *httptest.ResponseRecorder) ([]uint, int) {
	t.Helper()
	var resp types.ApiQueriesResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	var dq queries.DistributedQuery
	require.NoError(t, f.h.DB.Where("name = ?", resp.Name).First(&dq).Error)
	var ids []uint
	require.NoError(t, f.h.DB.Model(&queries.NodeQuery{}).Where("query_id = ?", dq.ID).Order("node_id").Pluck("node_id", &ids).Error)
	return ids, dq.Expected
}

func TestQueryRunTagTierNarrowsEnvTarget(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	rr := f.run(t, false, "tagger", types.ApiDistributedQueryRequest{})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	ids, expected := f.targeted(t, rr)
	require.Equal(t, []uint{f.n1.ID}, ids)
	require.Equal(t, 1, expected)
}

func TestQueryRunTagTierExplicitUUIDOutOfScope(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	rr := f.run(t, false, "tagger", types.ApiDistributedQueryRequest{UUIDs: []string{f.n2.UUID}})
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "node not found")
	var count int64
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Count(&count).Error)
	require.Zero(t, count)
	// An in-scope explicit node still works.
	rr = f.run(t, false, "tagger", types.ApiDistributedQueryRequest{UUIDs: []string{f.n1.UUID}})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestQueryRunCrossEnvUsesTargetEnvTier(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "mixed")
	f.tier(t, "mixed", f.env.UUID, users.QueryLevel, users.TierStandard)
	f.tier(t, "mixed", f.other.UUID, users.QueryLevel, users.TierTags, 9)
	rr := f.run(t, false, "mixed", types.ApiDistributedQueryRequest{Environments: []string{f.other.Name}})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	ids, expected := f.targeted(t, rr)
	require.Equal(t, []uint{f.b1.ID}, ids)
	require.Equal(t, 1, expected)
}

func TestQueryRunNoneTierForbidden(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "none")
	f.tier(t, "none", f.env.UUID, users.QueryLevel, users.TierNone)
	rr := f.run(t, false, "none", types.ApiDistributedQueryRequest{})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
}

func TestRawCarveSQLNeedsFullCarve(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "raw")
	f.tier(t, "raw", f.env.UUID, users.QueryLevel, users.TierFull)
	f.tier(t, "raw", f.env.UUID, users.CarveLevel, users.TierStandard)
	req := types.ApiDistributedQueryRequest{Query: "SELECT * FROM carves WHERE carve=1 AND path='/etc/hosts'"}
	rr := f.run(t, false, "raw", req)
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "full carve tier required for carve queries")
	f.tier(t, "raw", f.env.UUID, users.CarveLevel, users.TierFull)
	rr = f.run(t, false, "raw", req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestCarveRunTagTier(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "carver")
	f.tier(t, "carver", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	rr := f.run(t, true, "carver", types.ApiDistributedQueryRequest{})
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	ids, expected := f.targeted(t, rr)
	require.Equal(t, []uint{f.n1.ID}, ids)
	require.Equal(t, 1, expected)
}

func TestRunMissingNodeLooksLikeOutOfScope(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	f.tier(t, "tagger", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	missing := f.run(t, false, "tagger", types.ApiDistributedQueryRequest{Hosts: []string{"no-such-host"}})
	hidden := f.run(t, false, "tagger", types.ApiDistributedQueryRequest{Hosts: []string{f.n2.UUID}})
	require.Equal(t, http.StatusNotFound, missing.Code, missing.Body.String())
	require.Equal(t, hidden.Code, missing.Code)
	require.Equal(t, hidden.Body.String(), missing.Body.String())
	rr := f.run(t, true, "tagger", types.ApiDistributedQueryRequest{Hosts: []string{"no-such-host"}})
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	var count int64
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Count(&count).Error)
	require.Zero(t, count)
}

func TestRawCarveSQLNeedsFullCarveInTargetEnv(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "cross")
	f.tier(t, "cross", f.env.UUID, users.QueryLevel, users.TierFull)
	f.tier(t, "cross", f.env.UUID, users.CarveLevel, users.TierFull)
	f.tier(t, "cross", f.other.UUID, users.QueryLevel, users.TierStandard)
	rr := f.run(t, false, "cross", types.ApiDistributedQueryRequest{
		Query:        "SELECT * FROM carves WHERE carve=1 AND path='/etc/hosts'",
		Environments: []string{f.other.Name},
	})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "full carve tier required for carve queries")
	var count int64
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Count(&count).Error)
	require.Zero(t, count)
}
