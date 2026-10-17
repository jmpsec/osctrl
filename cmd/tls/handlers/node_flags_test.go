package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	nfNodeA     = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
	nfNodeOther = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB" // enrolled in another environment
	nfUnknown   = "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC"
	nfOverride  = "--extensions_autoload=/opt/ext.load\n--verbose\n"
	nfSHA       = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef"
)

type nodeFlagsFixture struct {
	db  *gorm.DB
	h   *HandlersTLS
	m   *nodeconfig.FlagsManager
	env environments.TLSEnvironment
}

func newNodeFlagsFixture(t *testing.T) *nodeFlagsFixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Secret: "osctrld-test-secret", Hostname: "osctrl.example", Flags: editedFlags}
	other := environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "other", Secret: "other-secret", Hostname: "osctrl.example", Flags: editedFlags}
	require.NoError(t, db.Create(&env).Error)
	require.NoError(t, db.Create(&other).Error)
	for _, n := range []nodes.OsqueryNode{
		{NodeKey: "key-a", UUID: nfNodeA, EnvironmentID: env.ID},
		{NodeKey: "key-other", UUID: nfNodeOther, EnvironmentID: other.ID},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	m, err := nodeconfig.NewFlagsManager(db, nil)
	require.NoError(t, err)
	h := CreateHandlersTLS(
		WithEnvs(envs),
		WithNodes(nodesRepo),
		WithFlagsOverrides(m),
		WithOsqueryValues(&config.YAMLConfigurationOsquery{Config: true, Logger: true}),
	)
	return &nodeFlagsFixture{db: db, h: h, m: m, env: env}
}

func (f *nodeFlagsFixture) set(t *testing.T, uuid string, envID uint, flags string, expires *time.Time) {
	t.Helper()
	_, err := f.m.Set(context.Background(), nodeconfig.FlagsOverride{NodeUUID: uuid, EnvironmentID: envID, Flags: flags, ExpiresAt: expires})
	require.NoError(t, err)
}

// flags returns what both osctrld endpoints serve for req, requiring they agree.
func (f *nodeFlagsFixture) flags(t *testing.T, req types.FlagsRequest) string {
	t.Helper()
	w := osctrldPost(t, f.h.FlagsHandler, f.env, req)
	require.Equal(t, http.StatusOK, w.Code)
	got := w.Body.String()
	w = osctrldPost(t, f.h.VerifyHandler, f.env, req)
	require.Equal(t, http.StatusOK, w.Code)
	var resp types.VerifyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, got, resp.Flags, "verify must serve the same flags as the flags endpoint")
	return got
}

func (f *nodeFlagsFixture) status(t *testing.T, uuid string) *nodeconfig.OsctrldStatus {
	t.Helper()
	st, err := f.m.Status(uuid)
	require.NoError(t, err)
	return st
}

func TestOsctrldFlagsMergesNodeOverride(t *testing.T) {
	f := newNodeFlagsFixture(t)
	f.set(t, nfNodeA, f.env.ID, nfOverride, nil)
	want, err := nodeconfig.MergeFlags(editedFlags, nfOverride)
	require.NoError(t, err)

	got := f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA})
	require.Equal(t, want, got)
	require.Contains(t, got, "--extensions_autoload=/opt/ext.load")
	require.Contains(t, got, "--verbose")
	// osquery reports UUIDs in either case; the lookup must still match.
	require.Equal(t, want, f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: strings.ToLower(nfNodeA)}))
}

func TestOsctrldFlagsWithoutUUIDServesEnvironment(t *testing.T) {
	f := newNodeFlagsFixture(t)
	f.set(t, nfNodeA, f.env.ID, nfOverride, nil)
	require.Equal(t, editedFlags, f.flags(t, types.FlagsRequest{Secret: f.env.Secret}))
	require.Nil(t, f.status(t, nfNodeA))
}

func TestOsctrldFlagsIgnoresForeignOrUnknownUUID(t *testing.T) {
	f := newNodeFlagsFixture(t)
	// An override stored for the foreign node in this environment must not be
	// reachable by naming that node against this environment.
	f.set(t, nfNodeOther, f.env.ID, nfOverride, nil)
	for _, uuid := range []string{nfNodeOther, nfUnknown, "not-a-uuid"} {
		require.Equal(t, editedFlags, f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: uuid}), uuid)
		require.Nil(t, f.status(t, uuid), uuid)
	}
}

func TestOsctrldFlagsRecordsFetchAndApply(t *testing.T) {
	f := newNodeFlagsFixture(t)
	before := time.Now().Add(-time.Second)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	apply := &types.OsctrldApplyStatus{Result: "rejected", SHA256: nfSHA, Error: "osqueryd refused", At: at}
	f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA, Apply: apply})

	st := f.status(t, nfNodeA)
	require.NotNil(t, st)
	require.Equal(t, f.env.ID, st.EnvironmentID)
	require.True(t, st.LastFetchedAt.After(before))
	require.Equal(t, "rejected", st.ApplyResult)
	require.Equal(t, nfSHA, st.ApplySHA256)
	require.Equal(t, "osqueryd refused", st.ApplyError)
	require.NotNil(t, st.ApplyAt)
	require.True(t, at.Equal(*st.ApplyAt))

	// osctrld may report the same status twice in one sync, and a request
	// without apply keeps the last reported one.
	f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA, Apply: apply})
	f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA})
	st = f.status(t, nfNodeA)
	require.Equal(t, "rejected", st.ApplyResult)
	require.Equal(t, nfSHA, st.ApplySHA256)
}

func TestOsctrldFlagsDropsInvalidApply(t *testing.T) {
	for name, apply := range map[string]*types.OsctrldApplyStatus{
		"unknown result": {Result: "pwned", SHA256: nfSHA},
		"empty result":   {SHA256: nfSHA},
		"short sha":      {Result: "ok", SHA256: "abc"},
		"non-hex sha":    {Result: "ok", SHA256: strings.Repeat("z", 64)},
		"long sha":       {Result: "ok", SHA256: nfSHA + "00"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newNodeFlagsFixture(t)
			f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA, Apply: apply})
			st := f.status(t, nfNodeA)
			require.NotNil(t, st, "the fetch is still recorded")
			require.False(t, st.LastFetchedAt.IsZero())
			require.Empty(t, st.ApplyResult)
			require.Empty(t, st.ApplySHA256)
			require.Nil(t, st.ApplyAt)
		})
	}
	t.Run("ok is accepted", func(t *testing.T) {
		f := newNodeFlagsFixture(t)
		f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA, Apply: &types.OsctrldApplyStatus{Result: "ok", SHA256: nfSHA, At: time.Now()}})
		require.Equal(t, "ok", f.status(t, nfNodeA).ApplyResult)
	})
}

func TestOsctrldFlagsExpiredOverrideNotApplied(t *testing.T) {
	f := newNodeFlagsFixture(t)
	past := time.Now().Add(-time.Minute)
	f.set(t, nfNodeA, f.env.ID, nfOverride, &past)
	require.Equal(t, editedFlags, f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA}))
	require.NotNil(t, f.status(t, nfNodeA), "the fetch is recorded even without an active override")
}

func TestOsctrldFlagsInvalidStoredOverrideFallsBack(t *testing.T) {
	f := newNodeFlagsFixture(t)
	// Bypass Set's validation, as a row written by an older or tampered writer would.
	require.NoError(t, f.db.Create(&nodeconfig.FlagsOverride{NodeUUID: nfNodeA, EnvironmentID: f.env.ID, Flags: "--tls_hostname=evil"}).Error)
	got := f.flags(t, types.FlagsRequest{Secret: f.env.Secret, UUID: nfNodeA})
	require.Equal(t, editedFlags, got)
	require.NotContains(t, got, "evil")
}

func TestOsctrldFlagsWrongSecretRecordsNothing(t *testing.T) {
	f := newNodeFlagsFixture(t)
	f.set(t, nfNodeA, f.env.ID, nfOverride, nil)
	req := types.FlagsRequest{Secret: "wrong", UUID: nfNodeA, Apply: &types.OsctrldApplyStatus{Result: "ok", SHA256: nfSHA}}
	require.Equal(t, http.StatusForbidden, osctrldPost(t, f.h.FlagsHandler, f.env, req).Code)
	require.Equal(t, http.StatusForbidden, osctrldPost(t, f.h.VerifyHandler, f.env, req).Code)
	require.Nil(t, f.status(t, nfNodeA))
}
