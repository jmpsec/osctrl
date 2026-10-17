package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const nodeFlagsEnvA = "--verbose=false\n--host_identifier=uuid\n--tls_server_certs=__CERT_FILE__\n--enroll_secret_path=__SECRET_FILE__"

func setupNodeFlagsHandlers(t *testing.T) (*HandlersApi, *gorm.DB, uint, uint, *nodeconfig.FlagsManager) {
	t.Helper()
	h, db, envA, envB, _ := setupNodeConfigHandlers(t)
	require.NoError(t, db.Model(&envA).Update("flags", nodeFlagsEnvA).Error)
	require.NoError(t, db.Model(&envB).Update("flags", "--verbose=true").Error)
	fm, err := nodeconfig.NewFlagsManager(db, nil)
	require.NoError(t, err)
	WithFlagsOverrides(fm)(h)
	return h, db, envA.ID, envB.ID, fm
}

func serveNodeFlags(t *testing.T, h *HandlersApi, method, user, env, node, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := nodeConfigRequest(method, user, env, node, body)
	switch method {
	case http.MethodGet:
		h.NodeFlagsGetHandler(rr, req)
	case http.MethodPut:
		h.NodeFlagsPutHandler(rr, req)
	case http.MethodDelete:
		h.NodeFlagsDeleteHandler(rr, req)
	default:
		t.Fatalf("unexpected method %s", method)
	}
	return rr
}

func decodeNodeFlags(t *testing.T, rr *httptest.ResponseRecorder) types.NodeFlagsResponse {
	t.Helper()
	var resp types.NodeFlagsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp), rr.Body.String())
	return resp
}

func flagsBody(t *testing.T, override string, expires *time.Time) string {
	t.Helper()
	raw, err := json.Marshal(types.NodeFlagsRequest{Override: override, ExpiresAt: expires})
	require.NoError(t, err)
	return string(raw)
}

func requireNoFlags(t *testing.T, fm *nodeconfig.FlagsManager, node string) {
	t.Helper()
	o, err := fm.Get(node)
	require.NoError(t, err)
	require.Nil(t, o)
}

func TestNodeFlagsPermissions(t *testing.T) {
	h, db, envA, envB, fm := setupNodeFlagsHandlers(t)

	rr := serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	cases := []struct {
		user, env, node, method, body string
		envID                         uint
	}{
		{"alice", "b", "NODE-B", http.MethodGet, "", envB},
		{"bob", "a", "NODE-A", http.MethodGet, "", envA},
		{"bob", "a", "NODE-A", http.MethodPut, flagsBody(t, "--verbose=true", nil), envA},
		{"bob", "a", "NODE-A", http.MethodDelete, "", envA},
	}
	for _, c := range cases {
		before := len(auditLines(t, db, auditlog.LogTypeEnvironment, c.envID))
		rr := serveNodeFlags(t, h, c.method, c.user, c.env, c.node, c.body)
		require.Equal(t, http.StatusForbidden, rr.Code, "%s %s %s", c.method, c.user, c.env)
		lines := auditLines(t, db, auditlog.LogTypeEnvironment, c.envID)
		require.Len(t, lines, before+1, "%s %s %s", c.method, c.user, c.env)
		require.Contains(t, lines[len(lines)-1], "denied access for user "+c.user)
	}
	requireNoFlags(t, fm, "NODE-A")

	rr = serveNodeFlags(t, h, http.MethodGet, "root", "b", "NODE-B", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestNodeFlagsPutAndGet(t *testing.T) {
	h, _, _, _, _ := setupNodeFlagsHandlers(t)
	override := "--verbose=true\n--host_detail_interval=60"
	rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, override, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, override, decodeNodeFlags(t, rr).Override)

	rr = serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeFlags(t, rr)
	want, err := nodeconfig.MergeFlags(nodeFlagsEnvA, override)
	require.NoError(t, err)
	require.Equal(t, nodeFlagsEnvA, got.Environment)
	require.Equal(t, override, got.Override)
	require.Equal(t, want, got.Applied)
	require.Contains(t, got.Applied, "--verbose=true")
	require.Contains(t, got.Applied, "--tls_server_certs=__CERT_FILE__")
	require.Equal(t, "alice", got.UpdatedBy)
	require.False(t, got.Expired)
	require.Nil(t, got.ExpiresAt)
	require.NotNil(t, got.UpdatedAt)
	require.Nil(t, got.Osctrld)
}

func TestNodeFlagsPutRefusesInvalid(t *testing.T) {
	h, _, _, _, fm := setupNodeFlagsHandlers(t)
	for override, want := range map[string]string{
		"--tls_hostname=evil":             "tls_hostname",
		"--notls_server_certs":            "notls_server_certs",
		"verbose=true":                    "not a flag",
		"--verbose=true\n--verbose=false": "verbose",
		"":                                "at least one flag",
	} {
		rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, override, nil))
		require.Equal(t, http.StatusBadRequest, rr.Code, override)
		require.Contains(t, rr.Body.String(), want, override)
		requireNoFlags(t, fm, "NODE-A")
	}
}

func TestNodeFlagsPutRefusesPastExpiry(t *testing.T) {
	h, _, _, _, fm := setupNodeFlagsHandlers(t)
	past := time.Now().Add(-time.Minute)
	rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, "--verbose=true", &past))
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	requireNoFlags(t, fm, "NODE-A")
}

func TestNodeFlagsPutRefusesOversizedBody(t *testing.T) {
	h, _, _, _, fm := setupNodeFlagsHandlers(t)
	big := "--verbose=true\n--x=" + strings.Repeat("a", 300<<10)
	rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, big, nil))
	require.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	requireNoFlags(t, fm, "NODE-A")
}

func TestNodeFlagsCrossEnvNodeNotFound(t *testing.T) {
	h, _, _, envB, fm := setupNodeFlagsHandlers(t)
	const existing = "--verbose=false"
	_, err := fm.Set(context.Background(), nodeconfig.FlagsOverride{NodeUUID: "NODE-B", EnvironmentID: envB, Flags: existing})
	require.NoError(t, err)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rr := serveNodeFlags(t, h, method, "alice", "a", "NODE-B", flagsBody(t, "--verbose=true", nil))
		require.Equal(t, http.StatusNotFound, rr.Code, method)
		o, err := fm.Get("NODE-B")
		require.NoError(t, err)
		require.NotNil(t, o, method)
		require.Equal(t, existing, o.Flags, method)
	}
}

func TestNodeFlagsIgnoresHostnameDecoy(t *testing.T) {
	h, db, envA, _, fm := setupNodeFlagsHandlers(t)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "DECOY-UUID", Hostname: "TARGET-UUID", Localname: "decoy-local", EnvironmentID: envA, Environment: "a"}).Error)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "TARGET-UUID", EnvironmentID: envA, Environment: "a"}).Error)
	_, err := fm.Set(context.Background(), nodeconfig.FlagsOverride{NodeUUID: "DECOY-UUID", EnvironmentID: envA, Flags: "--verbose=false"})
	require.NoError(t, err)
	for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodDelete} {
		rr := serveNodeFlags(t, h, method, "alice", "a", "TARGET-UUID", flagsBody(t, "--verbose=true", nil))
		require.Equal(t, http.StatusOK, rr.Code, "%s %s", method, rr.Body.String())
		if method == http.MethodGet {
			require.Equal(t, "--verbose=true", decodeNodeFlags(t, rr).Override)
		}
		decoy, err := fm.Get("DECOY-UUID")
		require.NoError(t, err)
		require.NotNil(t, decoy, method)
		require.Equal(t, "--verbose=false", decoy.Flags, method)
	}
	rr := serveNodeFlags(t, h, http.MethodGet, "alice", "a", "decoy-local", "")
	require.Equal(t, http.StatusNotFound, rr.Code)
}

func TestNodeFlagsExpiredReportedNotApplied(t *testing.T) {
	h, db, envA, _, _ := setupNodeFlagsHandlers(t)
	past := time.Now().Add(-time.Hour)
	require.NoError(t, db.Create(&nodeconfig.FlagsOverride{NodeUUID: "NODE-A", EnvironmentID: envA, Flags: "--verbose=true", ExpiresAt: &past, UpdatedBy: "alice"}).Error)
	rr := serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := decodeNodeFlags(t, rr)
	require.True(t, got.Expired)
	require.Equal(t, "--verbose=true", got.Override)
	require.Equal(t, got.Environment, got.Applied)
	require.NotNil(t, got.ExpiresAt)
}

func TestNodeFlagsOtherEnvRowNotReported(t *testing.T) {
	h, db, _, envB, _ := setupNodeFlagsHandlers(t)
	require.NoError(t, db.Create(&nodeconfig.FlagsOverride{NodeUUID: "NODE-A", EnvironmentID: envB, Flags: "--verbose=true", UpdatedBy: "root"}).Error)
	got := decodeNodeFlags(t, serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", ""))
	require.Empty(t, got.Override)
	require.Empty(t, got.UpdatedBy)
	require.Equal(t, nodeFlagsEnvA, got.Applied)
}

func TestNodeFlagsDeleteAndAudit(t *testing.T) {
	h, db, envA, _, fm := setupNodeFlagsHandlers(t)
	first := "--verbose=true"
	rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, first, nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	second := "--verbose=false"
	rr = serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, second, &expires))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = serveNodeFlags(t, h, http.MethodDelete, "alice", "a", "NODE-A", "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	del := decodeNodeFlags(t, rr)
	require.Empty(t, del.Override)
	require.Equal(t, del.Environment, del.Applied)
	requireNoFlags(t, fm, "NODE-A")

	lines := auditLines(t, db, auditlog.LogTypeNode, envA)
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], "set flags override on node NODE-A (expires never): before=none after="+first)
	require.Contains(t, lines[1], "set flags override on node NODE-A (expires "+expires.Format(time.RFC3339)+"): before="+first+" after="+second)
	require.Contains(t, lines[2], "removed flags override on node NODE-A: before="+second)
}

func TestNodeFlagsConflicts(t *testing.T) {
	h, _, envA, _, _ := setupNodeFlagsHandlers(t)
	// nodeConfigEnvA sets options.verbose.
	rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, "--verbose=true\n--host_detail_interval=60", nil))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, []string{"verbose"}, decodeNodeFlags(t, rr).Conflicts)

	// The node's configuration override counts too.
	_, err := h.NodeConfig.Set(context.Background(), nodeconfig.Override{NodeUUID: "NODE-A", EnvironmentID: envA, Config: `{"options":{"host_detail_interval":30}}`})
	require.NoError(t, err)
	got := decodeNodeFlags(t, serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", ""))
	require.Equal(t, []string{"host_detail_interval", "verbose"}, got.Conflicts)
}

func TestNodeFlagsOsctrldStatus(t *testing.T) {
	get := func(t *testing.T, h *HandlersApi) types.NodeFlagsResponse {
		rr := serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", "")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		return decodeNodeFlags(t, rr)
	}
	set := func(t *testing.T, h *HandlersApi) {
		rr := serveNodeFlags(t, h, http.MethodPut, "alice", "a", "NODE-A", flagsBody(t, "--verbose=true", nil))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}
	rejected := func(at time.Time) *types.OsctrldApplyStatus {
		return &types.OsctrldApplyStatus{Result: "rejected", Error: "bad flag", At: at}
	}

	t.Run("never seen", func(t *testing.T) {
		h, _, _, _, _ := setupNodeFlagsHandlers(t)
		set(t, h)
		rr := serveNodeFlags(t, h, http.MethodGet, "alice", "a", "NODE-A", "")
		require.Contains(t, rr.Body.String(), `"osctrld":null`)
	})
	t.Run("rejected after override update", func(t *testing.T) {
		h, _, envA, _, fm := setupNodeFlagsHandlers(t)
		set(t, h)
		at := time.Now().Add(time.Second)
		require.NoError(t, fm.RecordFetch("NODE-A", envA, at, rejected(at)))
		got := get(t, h)
		require.NotNil(t, got.Osctrld)
		require.True(t, got.Osctrld.RejectedCurrent)
		require.Equal(t, "rejected", got.Osctrld.ApplyResult)
		require.Equal(t, "bad flag", got.Osctrld.ApplyError)
		require.NotNil(t, got.Osctrld.ApplyAt)
		require.False(t, got.Osctrld.LastFetchedAt.IsZero())
	})
	t.Run("rejected before override update", func(t *testing.T) {
		h, _, envA, _, fm := setupNodeFlagsHandlers(t)
		at := time.Now().Add(-time.Hour)
		require.NoError(t, fm.RecordFetch("NODE-A", envA, at, rejected(at)))
		set(t, h)
		got := get(t, h)
		require.NotNil(t, got.Osctrld)
		require.False(t, got.Osctrld.RejectedCurrent)
	})
	t.Run("future apply_at clamped to fetch time", func(t *testing.T) {
		h, _, envA, _, fm := setupNodeFlagsHandlers(t)
		require.NoError(t, fm.RecordFetch("NODE-A", envA, time.Now().Add(-time.Hour), rejected(time.Now().AddDate(100, 0, 0))))
		set(t, h)
		got := get(t, h)
		require.NotNil(t, got.Osctrld)
		require.False(t, got.Osctrld.RejectedCurrent)
	})
	t.Run("rejected but override expired", func(t *testing.T) {
		h, db, envA, _, fm := setupNodeFlagsHandlers(t)
		past := time.Now().Add(-time.Minute)
		require.NoError(t, db.Create(&nodeconfig.FlagsOverride{NodeUUID: "NODE-A", EnvironmentID: envA, Flags: "--verbose=true", ExpiresAt: &past, UpdatedBy: "alice"}).Error)
		at := time.Now().Add(time.Second)
		require.NoError(t, fm.RecordFetch("NODE-A", envA, at, rejected(at)))
		got := get(t, h)
		require.NotNil(t, got.Osctrld)
		require.Equal(t, "rejected", got.Osctrld.ApplyResult)
		require.False(t, got.Osctrld.RejectedCurrent)
	})
	t.Run("rejected without override", func(t *testing.T) {
		h, _, envA, _, fm := setupNodeFlagsHandlers(t)
		at := time.Now()
		require.NoError(t, fm.RecordFetch("NODE-A", envA, at, rejected(at)))
		got := get(t, h)
		require.NotNil(t, got.Osctrld)
		require.False(t, got.Osctrld.RejectedCurrent)
	})
	t.Run("status from another environment not reported", func(t *testing.T) {
		h, _, _, envB, fm := setupNodeFlagsHandlers(t)
		at := time.Now()
		require.NoError(t, fm.RecordFetch("NODE-A", envB, at, rejected(at)))
		require.Nil(t, get(t, h).Osctrld)
	})
}

func TestDeleteNodeRemovesFlagsOverrideAndStatus(t *testing.T) {
	deleteNode := func(t *testing.T, h *HandlersApi) {
		body, err := json.Marshal(types.ApiNodeGenericRequest{UUID: "NODE-A"})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/a/delete", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.SetPathValue("env", "a")
		req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"}))
		rr := httptest.NewRecorder()
		h.DeleteNodeHandler(rr, req)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	}

	t.Run("removes rows", func(t *testing.T) {
		h, db, envA, _, fm := setupNodeFlagsHandlers(t)
		_, err := fm.Set(context.Background(), nodeconfig.FlagsOverride{NodeUUID: "NODE-A", EnvironmentID: envA, Flags: "--verbose=true"})
		require.NoError(t, err)
		require.NoError(t, fm.RecordFetch("NODE-A", envA, time.Now(), nil))
		deleteNode(t, h)
		var n int64
		require.NoError(t, db.Unscoped().Model(&nodeconfig.FlagsOverride{}).Count(&n).Error)
		require.Zero(t, n)
		require.NoError(t, db.Unscoped().Model(&nodeconfig.OsctrldStatus{}).Count(&n).Error)
		require.Zero(t, n)
	})
	t.Run("nil manager", func(t *testing.T) {
		h, _, _, _, _ := setupNodeFlagsHandlers(t)
		h.FlagsOverrides = nil
		deleteNode(t, h)
	})
}
