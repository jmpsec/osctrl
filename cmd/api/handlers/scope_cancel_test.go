package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func (f tierFixture) pendingFor(t *testing.T, creator, qtype string, nodeID uint) uint {
	t.Helper()
	dq := queries.DistributedQuery{Name: creator + qtype + string(rune('a'+nodeID)), Creator: creator, Type: qtype, EnvironmentID: f.env.ID, Expected: 1}
	require.NoError(t, f.h.DB.Create(&dq).Error)
	nq := queries.NodeQuery{NodeID: nodeID, QueryID: dq.ID, Status: queries.DistributedQueryStatusPending}
	require.NoError(t, f.h.DB.Create(&nq).Error)
	return nq.ID
}

func (f tierFixture) pendingExists(t *testing.T, id uint) bool {
	t.Helper()
	var c int64
	require.NoError(t, f.h.DB.Unscoped().Model(&queries.NodeQuery{}).Where("id = ?", id).Count(&c).Error)
	return c > 0
}

func TestUntagCancelsTagScopedPending(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	f.tier(t, "tagger", f.env.UUID, users.CarveLevel, users.TierTags, 7)
	q := f.pendingFor(t, "tagger", queries.StandardQueryType, f.n1.ID)
	c := f.pendingFor(t, "tagger", queries.CarveQueryType, f.n1.ID)
	// Still tagged: nothing is cancelled.
	require.NoError(t, f.h.cancelOutOfScope(context.Background(), []uint{f.n1.ID}))
	require.True(t, f.pendingExists(t, q))
	require.True(t, f.pendingExists(t, c))
	require.NoError(t, f.h.DB.Where("node_id = ?", f.n1.ID).Delete(&tags.TaggedNode{}).Error)
	require.NoError(t, f.h.cancelOutOfScope(context.Background(), []uint{f.n1.ID}))
	require.False(t, f.pendingExists(t, q))
	require.False(t, f.pendingExists(t, c))
	// The cancelled target no longer counts toward the query's Expected.
	var expected []int
	require.NoError(t, f.h.DB.Model(&queries.DistributedQuery{}).Where("creator = ?", "tagger").Pluck("expected", &expected).Error)
	require.Equal(t, []int{0, 0}, expected)
}

func TestUntagKeepsStandardPending(t *testing.T) {
	f := setupTiers(t)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	id := f.pendingFor(t, "std", queries.StandardQueryType, f.n1.ID)
	require.NoError(t, f.h.DB.Where("node_id = ?", f.n1.ID).Delete(&tags.TaggedNode{}).Error)
	require.NoError(t, f.h.cancelOutOfScope(context.Background(), []uint{f.n1.ID}))
	require.True(t, f.pendingExists(t, id))
}

func TestCancelOutOfScopeFailsClosed(t *testing.T) {
	f := setupTiers(t)
	// Creator no longer exists.
	gone := f.pendingFor(t, "ghost", queries.StandardQueryType, f.n1.ID)
	// Cross-env: judged in the node's env (other), where the creator has only tag 9.
	f.user(t, "mixed")
	f.tier(t, "mixed", f.env.UUID, users.QueryLevel, users.TierStandard)
	f.tier(t, "mixed", f.other.UUID, users.QueryLevel, users.TierTags, 9)
	keep := f.pendingFor(t, "mixed", queries.StandardQueryType, f.b1.ID)
	drop := f.pendingFor(t, "mixed", queries.StandardQueryType, f.b2.ID)
	require.NoError(t, f.h.cancelOutOfScope(context.Background(), []uint{f.n1.ID, f.b1.ID, f.b2.ID}))
	require.False(t, f.pendingExists(t, gone))
	require.True(t, f.pendingExists(t, keep))
	require.False(t, f.pendingExists(t, drop))
}

func TestTagDeleteCancelsPending(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	require.NoError(t, f.h.Tags.NewTag("seven", "", "", "", "root", f.env.ID, false, tags.TagTypeTag, ""))
	tag, err := f.h.Tags.Get("seven", f.env.ID)
	require.NoError(t, err)
	// Tag 7 in the fixture is a bare id; point the grant and tagging at the real tag.
	require.NoError(t, f.h.DB.Model(&tags.TaggedNode{}).Where("admin_tag_id = 7").Update("admin_tag_id", tag.ID).Error)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, tag.ID)
	id := f.pendingFor(t, "tagger", queries.StandardQueryType, f.n1.ID)

	r := consoleRequest(http.MethodPost, "/tags", mustJSON(t, types.ApiTagsRequest{Name: "seven"}), "alice")
	r.SetPathValue("env", f.env.Name)
	r.SetPathValue("action", tags.ActionRemove)
	rr := httptest.NewRecorder()
	f.h.TagsActionHandler(rr, r)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.False(t, f.pendingExists(t, id))
	ids, err := f.h.Users.ScopeTagIDsContext(context.Background(), "tagger", f.env.UUID)
	require.NoError(t, err)
	require.Empty(t, ids)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
