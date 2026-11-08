package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
)

func (f tierFixture) tagAction(t *testing.T, user, action string, req types.ApiTagsRequest) *httptest.ResponseRecorder {
	r := consoleRequest(http.MethodPost, "/tags", mustJSON(t, req), user)
	r.RemoteAddr = "127.0.0.1:1234"
	r.SetPathValue("env", f.env.Name)
	r.SetPathValue("action", action)
	rr := httptest.NewRecorder()
	f.h.TagsActionHandler(rr, r)
	return rr
}

func boolPtr(b bool) *bool { return &b }

// pendingSetup gives a standard user "std" and the env admin "alice" a pending query on n1 (tag 7).
func pendingSetup(t *testing.T) (tierFixture, uint, uint) {
	t.Helper()
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	f.tier(t, "alice", f.env.UUID, users.QueryLevel, users.TierFull)
	std := f.pendingFor(t, "std", queries.StandardQueryType, f.n1.ID)
	admin := f.pendingFor(t, "alice", queries.StandardQueryType, f.n1.ID)
	return f, std, admin
}

func TestTagAddSensitive(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	rr := f.tagAction(t, "alice", tags.ActionAdd, types.ApiTagsRequest{Name: "secret", Sensitive: boolPtr(true)})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	tag, err := f.h.Tags.Get("secret", f.env.ID)
	require.NoError(t, err)
	require.True(t, tag.Sensitive)
	list, err := f.h.Tags.GetByEnv(f.env.ID)
	require.NoError(t, err)
	require.Contains(t, string(mustJSON(t, list)), `"sensitive":true`)
}

func TestTagEditMarksSensitive(t *testing.T) {
	f, std, admin := pendingSetup(t)
	f.user(t, "tagger")
	f.tier(t, "tagger", f.env.UUID, users.QueryLevel, users.TierTags, 7)
	rr := f.tagAction(t, "alice", tags.ActionEdit, types.ApiTagsRequest{Name: "t7", Sensitive: boolPtr(true)})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	tag, err := f.h.Tags.Get("t7", f.env.ID)
	require.NoError(t, err)
	require.True(t, tag.Sensitive)
	require.False(t, f.pendingExists(t, std))
	require.True(t, f.pendingExists(t, admin))
	ids, err := f.h.Users.ScopeTagIDsContext(context.Background(), "tagger", f.env.UUID)
	require.NoError(t, err)
	require.Empty(t, ids)
}

func TestTagEditUnmarkKeepsPending(t *testing.T) {
	f, std, admin := pendingSetup(t)
	f.h.DB.Model(&tags.AdminTag{}).Where("id = 7").Update("sensitive", true)
	rr := f.tagAction(t, "alice", tags.ActionEdit, types.ApiTagsRequest{Name: "t7", Sensitive: boolPtr(false)})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	tag, err := f.h.Tags.Get("t7", f.env.ID)
	require.NoError(t, err)
	require.False(t, tag.Sensitive)
	require.True(t, f.pendingExists(t, std))
	require.True(t, f.pendingExists(t, admin))
}

func TestTagNodeWithSensitiveTagCancels(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	n3 := nodes.OsqueryNode{UUID: "N3", Platform: "linux", EnvironmentID: f.env.ID, Environment: f.env.Name, LastSeen: time.Now()}
	require.NoError(t, f.h.DB.Create(&n3).Error)
	require.NoError(t, f.h.Tags.NewTag("nine", "", "", "", "root", f.env.ID, false, tags.TagTypeTag, ""))
	var nine tags.AdminTag
	require.NoError(t, f.h.DB.Where("name = ?", "nine").First(&nine).Error)
	require.NoError(t, f.h.Tags.ChangeSensitive(&nine, true))
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	id := f.pendingFor(t, "std", queries.StandardQueryType, n3.ID)

	r := consoleRequest(http.MethodPost, "/nodes/tag", []byte(`{"uuid":"N3","tag":"nine"}`), "alice")
	r.RemoteAddr = "127.0.0.1:1234"
	r.SetPathValue("env", f.env.Name)
	rr := httptest.NewRecorder()
	f.h.TagNodeHandler(rr, r)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.False(t, f.pendingExists(t, id))
}

func TestScopeTagRejectsSensitive(t *testing.T) {
	h := setupRoles(t)
	h.Tags = tags.CreateTagManager(h.DB)
	dev, err := h.Envs.GetByUUID("uuid-dev")
	require.NoError(t, err)
	require.NoError(t, h.Tags.NewTag("web", "", "", "", "root", dev.ID, false, tags.TagTypeCustom, ""))
	tag, err := h.Tags.Get("web", dev.ID)
	require.NoError(t, err)
	require.NoError(t, h.Tags.ChangeSensitive(&tag, true))
	rr := roReq(h, "root", http.MethodPost, "/api/v1/users/bob/permissions",
		fmt.Sprintf(`{"env_uuid":"uuid-dev","access":{"user":true,"query_tier":"tags","scope_tags":[%d]}}`, tag.ID),
		map[string]string{"username": "bob"}, h.SetUserPermissionsHandler)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "sensitive tag cannot be a scope tag")
}

func TestTagEditSensitiveNeedsEnvAdmin(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	f.user(t, "std")
	f.tier(t, "std", f.env.UUID, users.QueryLevel, users.TierStandard)
	rr := f.tagAction(t, "std", tags.ActionEdit, types.ApiTagsRequest{Name: "t7", Sensitive: boolPtr(true)})
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	tag, err := f.h.Tags.Get("t7", f.env.ID)
	require.NoError(t, err)
	require.False(t, tag.Sensitive)
}

func TestTagEditSensitiveAudited(t *testing.T) {
	f := setupTiers(t)
	f.h.Tags = tags.CreateTagManager(f.h.DB)
	f.h.AuditLog.Enabled = true
	rr := f.tagAction(t, "alice", tags.ActionEdit, types.ApiTagsRequest{Name: "t7", Sensitive: boolPtr(true)})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var entry auditlog.AuditLog
	require.NoError(t, f.h.DB.Where("log_type = ?", auditlog.LogTypeTag).First(&entry).Error)
	require.Contains(t, entry.Line, "sensitive")
}
