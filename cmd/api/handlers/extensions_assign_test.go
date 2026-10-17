package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type assignFixture struct {
	h          *HandlersApi
	db         *gorm.DB
	envA, envB environments.TLSEnvironment
	mgr        *extensions.Manager
	// osq has a linux file, win a windows file, cmd is command execution
	// with a linux file.
	osq, win, cmd *extensions.Extension
}

// setupAssignHandlers: alice is admin of env a, root a super admin, bob
// nothing. NODE-A (ubuntu) is in a, NODE-B in b.
func setupAssignHandlers(t *testing.T) assignFixture {
	t.Helper()
	h, db, envA, envB, _ := setupNodeConfigHandlers(t)
	mgr, err := extensions.NewManager(db)
	require.NoError(t, err)
	WithExtensions(mgr)(h)
	require.NoError(t, db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", "ubuntu").Error)
	mk := func(name, platform, arch string, cmdExec bool) *extensions.Extension {
		e, err := mgr.Create(extensions.Extension{Name: name, CommandExecution: cmdExec, CreatedBy: "root"})
		require.NoError(t, err)
		_, err = mgr.PutFile(context.Background(), e.ID, platform, arch, name, strings.NewReader(name), "root")
		require.NoError(t, err)
		return e
	}
	return assignFixture{
		h: h, db: db, envA: envA, envB: envB, mgr: mgr,
		osq: mk("osq", "linux", "amd64", false),
		win: mk("win", "windows", "amd64", false),
		cmd: mk("cmd", "linux", "arm64", true),
	}
}

func callEnvExts(env string) extCall {
	return extCall{http.MethodGet, "/api/v1/environments/extensions/" + env,
		func(h *HandlersApi) http.HandlerFunc { return h.EnvExtensionsHandler }, map[string]string{"env": env}}
}

func callEnvExt(method, env string, id uint) extCall {
	hf := func(h *HandlersApi) http.HandlerFunc { return h.EnvExtensionAssignHandler }
	if method == http.MethodDelete {
		hf = func(h *HandlersApi) http.HandlerFunc { return h.EnvExtensionRemoveHandler }
	}
	return extCall{method, fmt.Sprintf("/api/v1/environments/extensions/%s/%d", env, id), hf,
		map[string]string{"env": env, "id": fmt.Sprint(id)}}
}

func callNodeExts(env, uuid string) extCall {
	return extCall{http.MethodGet, "/api/v1/nodes/" + env + "/node/" + uuid + "/extensions",
		func(h *HandlersApi) http.HandlerFunc { return h.NodeExtensionsHandler }, map[string]string{"env": env, "uuid": uuid}}
}

func callNodeExt(method, env, uuid string, id uint) extCall {
	hf := func(h *HandlersApi) http.HandlerFunc { return h.NodeExtensionAssignHandler }
	if method == http.MethodDelete {
		hf = func(h *HandlersApi) http.HandlerFunc { return h.NodeExtensionRemoveHandler }
	}
	return extCall{method, fmt.Sprintf("/api/v1/nodes/%s/node/%s/extensions/%d", env, uuid, id), hf,
		map[string]string{"env": env, "uuid": uuid, "id": fmt.Sprint(id)}}
}

func names(s []types.ExtensionSummary) []string {
	out := []string{}
	for _, e := range s {
		out = append(out, e.Name)
	}
	return out
}

func envExts(t *testing.T, f assignFixture, user string) types.EnvironmentExtensionsResponse {
	t.Helper()
	rr := extReq(t, f.h, callEnvExts(f.envA.Name), user, nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.EnvironmentExtensionsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func nodeExts(t *testing.T, f assignFixture, user string) types.NodeExtensionsResponse {
	t.Helper()
	rr := extReq(t, f.h, callNodeExts(f.envA.Name, "NODE-A"), user, nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.NodeExtensionsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func expiresBody(t *testing.T, at *time.Time) *bytes.Reader {
	t.Helper()
	raw, err := json.Marshal(types.NodeExtensionAssignRequest{ExpiresAt: at})
	require.NoError(t, err)
	return bytes.NewReader(raw)
}

func TestEnvExtensionsAssign(t *testing.T) {
	f := setupAssignHandlers(t)

	got := envExts(t, f, "alice")
	require.Empty(t, got.Assigned)
	require.Equal(t, []string{"osq", "win"}, names(got.Available), "command-execution extensions are never available to environments")
	require.Equal(t, []string{"linux"}, got.Available[0].Platforms)

	rr := extReq(t, f.h, callEnvExt(http.MethodPut, f.envA.Name, f.osq.ID), "alice", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got = envExts(t, f, "alice")
	require.Equal(t, []string{"osq"}, names(got.Assigned))
	require.Equal(t, []string{"win"}, names(got.Available))

	rr = extReq(t, f.h, callEnvExt(http.MethodPut, f.envA.Name, f.cmd.ID), "alice", nil, "")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, callEnvExt(http.MethodPut, f.envA.Name, 999), "alice", nil, "")
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())

	rr = extReq(t, f.h, callEnvExt(http.MethodDelete, f.envA.Name, f.osq.ID), "alice", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Empty(t, envExts(t, f, "alice").Assigned)
	// Removing an extension that is not assigned removes and audits nothing.
	for _, id := range []uint{f.osq.ID, f.win.ID} {
		rr = extReq(t, f.h, callEnvExt(http.MethodDelete, f.envA.Name, id), "alice", nil, "")
		require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	}

	lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
	require.Len(t, lines, 2)
	require.Equal(t, "user alice performed environment action: assigned extension osq to environment a", lines[0])
	require.Equal(t, "user alice performed environment action: removed extension osq from environment a", lines[1])
}

func TestEnvExtensionsPermissions(t *testing.T) {
	f := setupAssignHandlers(t)
	for _, c := range []struct {
		user string
		env  environments.TLSEnvironment
	}{{"bob", f.envA}, {"alice", f.envB}} {
		for _, call := range []extCall{
			callEnvExts(c.env.Name),
			callEnvExt(http.MethodPut, c.env.Name, f.osq.ID),
			callEnvExt(http.MethodDelete, c.env.Name, f.osq.ID),
		} {
			before := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, c.env.ID))
			rr := extReq(t, f.h, call, c.user, nil, "")
			require.Equal(t, http.StatusForbidden, rr.Code, "%s %s %s", c.user, call.method, call.path)
			lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, c.env.ID)
			require.Len(t, lines, before+1, "%s %s %s", c.user, call.method, call.path)
			require.Contains(t, lines[len(lines)-1], "denied access for user "+c.user)
		}
	}
	for _, env := range []uint{f.envA.ID, f.envB.ID} {
		assigned, err := f.mgr.EnvExtensions(env)
		require.NoError(t, err)
		require.Empty(t, assigned)
	}
}

func TestNodeExtensionsView(t *testing.T) {
	f := setupAssignHandlers(t)
	require.NoError(t, f.mgr.AssignEnv(f.envA.ID, f.osq.ID, "alice"))
	require.NoError(t, f.mgr.AssignEnv(f.envA.ID, f.win.ID, "alice"))
	_, err := f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, nil, "root")
	require.NoError(t, err)
	at := time.Now().UTC().Truncate(time.Second)
	sha := strings.Repeat("a", 64)
	require.NoError(t, f.mgr.RecordStatus("NODE-A", f.envA.ID, []types.OsctrldExtensionStatus{
		{Name: "osq", SHA256: sha, Result: "rejected", Error: "<b>bad</b>", At: at},
	}, at))
	// Not served in env a, so not reported there.
	require.NoError(t, f.mgr.RecordStatus("NODE-A", f.envB.ID, []types.OsctrldExtensionStatus{
		{Name: "win", SHA256: sha, Result: "ok", At: at},
	}, at))

	got := nodeExts(t, f, "alice")
	require.Nil(t, got.Library, "only super admins see the command-execution library")
	require.Equal(t, []types.NodeExtensionEffective{
		{Name: "cmd", Source: "host", CommandExecution: true, Platforms: []string{"linux"}, Available: true},
		{Name: "osq", Source: "environment", Platforms: []string{"linux"}, Available: true},
		{Name: "win", Source: "environment", Platforms: []string{"windows"}, Available: false},
	}, got.Effective)
	require.Len(t, got.Assignments, 1)
	require.Equal(t, f.cmd.ID, got.Assignments[0].ExtensionID)
	require.Equal(t, "cmd", got.Assignments[0].Name)
	require.Equal(t, "root", got.Assignments[0].CreatedBy)
	require.Nil(t, got.Assignments[0].ExpiresAt)
	require.False(t, got.Assignments[0].Expired)
	require.Len(t, got.Status, 1)
	require.Equal(t, "osq", got.Status[0].Name)
	require.Equal(t, sha, got.Status[0].SHA256)
	require.Equal(t, "rejected", got.Status[0].Result)
	require.Equal(t, "<b>bad</b>", got.Status[0].Error)
	require.True(t, at.Equal(*got.Status[0].At))

	root := nodeExts(t, f, "root")
	require.Equal(t, []string{"cmd"}, names(root.Library))

	// An expired assignment is listed but not effective.
	past := time.Now().Add(-time.Hour)
	_, err = f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, &past, "root")
	require.NoError(t, err)
	got = nodeExts(t, f, "alice")
	require.True(t, got.Assignments[0].Expired)
	require.Equal(t, []string{"osq", "win"}, []string{got.Effective[0].Name, got.Effective[1].Name})

	// Cross-environment node and environment.
	rr := extReq(t, f.h, callNodeExts(f.envA.Name, "NODE-B"), "alice", nil, "")
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, callNodeExts(f.envB.Name, "NODE-B"), "alice", nil, "")
	require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
}

func TestNodeExtensionAssign(t *testing.T) {
	f := setupAssignHandlers(t)
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	// Environment admins and others are refused, and audited.
	for _, user := range []string{"alice", "bob"} {
		for _, call := range []extCall{
			callNodeExt(http.MethodPut, f.envA.Name, "NODE-A", f.cmd.ID),
			callNodeExt(http.MethodDelete, f.envA.Name, "NODE-A", f.cmd.ID),
		} {
			before := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
			rr := extReq(t, f.h, call, user, expiresBody(t, &future), "application/json")
			require.Equal(t, http.StatusForbidden, rr.Code, "%s %s", user, call.method)
			lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
			require.Len(t, lines, before+1, "%s %s", user, call.method)
			require.Contains(t, lines[len(lines)-1], "denied access for user "+user)
		}
	}
	rows, err := f.mgr.NodeAssignments("NODE-A")
	require.NoError(t, err)
	require.Empty(t, rows)

	put := callNodeExt(http.MethodPut, f.envA.Name, "node-a", f.cmd.ID)
	past := time.Now().Add(-time.Minute)
	rr := extReq(t, f.h, put, "root", expiresBody(t, &past), "application/json")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, put, "root", strings.NewReader("not json"), "application/json")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, callNodeExt(http.MethodPut, f.envA.Name, "NODE-A", f.osq.ID), "root", expiresBody(t, nil), "application/json")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, callNodeExt(http.MethodPut, f.envA.Name, "NODE-A", 999), "root", expiresBody(t, nil), "application/json")
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	rr = extReq(t, f.h, callNodeExt(http.MethodPut, f.envA.Name, "NODE-B", f.cmd.ID), "root", expiresBody(t, nil), "application/json")
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())

	// The path UUID is lower case; the assignment uses the node row's.
	rr = extReq(t, f.h, put, "root", expiresBody(t, &future), "application/json")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var got types.NodeExtensionsResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	require.Len(t, got.Assignments, 1)
	require.True(t, future.Equal(*got.Assignments[0].ExpiresAt))
	rows, err = f.mgr.NodeAssignments("NODE-A")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, f.envA.ID, rows[0].EnvironmentID)

	// The expiry must be given explicitly: a missing, misspelled or extra key,
	// or trailing data, must not grant command execution without expiry.
	for _, body := range []string{
		`{}`,
		`{"expiresAt":"` + future.Format(time.RFC3339) + `"}`,
		`{"expires":null}`,
		`{"expires_at":null,"extra":1}`,
		`{"expires_at":null} {}`,
		`{"expires_at":null}x`,
		``,
	} {
		rr = extReq(t, f.h, put, "root", strings.NewReader(body), "application/json")
		require.Equal(t, http.StatusBadRequest, rr.Code, "%s: %s", body, rr.Body.String())
		rows, err = f.mgr.NodeAssignments("NODE-A")
		require.NoError(t, err)
		require.True(t, future.Equal(*rows[0].ExpiresAt), "%s must not change the assignment", body)
	}

	rr = extReq(t, f.h, put, "root", strings.NewReader(`{"expires_at":null}`), "application/json")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rows, err = f.mgr.NodeAssignments("NODE-A")
	require.NoError(t, err)
	require.Nil(t, rows[0].ExpiresAt)

	rr = extReq(t, f.h, callNodeExt(http.MethodDelete, f.envA.Name, "node-a", f.cmd.ID), "root", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rows, err = f.mgr.NodeAssignments("NODE-A")
	require.NoError(t, err)
	require.Empty(t, rows)
	// Nothing assigned: an ordinary extension's ID, or a repeat removal, is
	// 404 and not audited.
	for _, id := range []uint{f.osq.ID, f.cmd.ID} {
		rr = extReq(t, f.h, callNodeExt(http.MethodDelete, f.envA.Name, "NODE-A", id), "root", nil, "")
		require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	}

	lines := auditLines(t, f.db, auditlog.LogTypeNode, f.envA.ID)
	require.Equal(t, []string{
		"user root performed node action: allowed command execution on node NODE-A via extension cmd (expires " + future.Format(time.RFC3339) + ")",
		"user root performed node action: allowed command execution on node NODE-A via extension cmd (expires never)",
		"user root performed node action: removed command execution extension cmd from node NODE-A",
	}, lines)
}

func TestDeleteNodeRemovesExtensions(t *testing.T) {
	deleteNode := func(t *testing.T, h *HandlersApi) {
		body, err := json.Marshal(types.ApiNodeGenericRequest{UUID: "node-a"})
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
		f := setupAssignHandlers(t)
		_, err := f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, nil, "root")
		require.NoError(t, err)
		require.NoError(t, f.mgr.RecordStatus("NODE-A", f.envA.ID, []types.OsctrldExtensionStatus{
			{Name: "cmd", SHA256: strings.Repeat("a", 64), Result: "ok", At: time.Now()},
		}, time.Now()))
		deleteNode(t, f.h)
		rows, err := f.mgr.NodeAssignments("NODE-A")
		require.NoError(t, err)
		require.Empty(t, rows)
		st, err := f.mgr.NodeStatuses("NODE-A")
		require.NoError(t, err)
		require.Empty(t, st)
	})
	t.Run("nil manager", func(t *testing.T) {
		f := setupAssignHandlers(t)
		f.h.Extensions = nil
		deleteNode(t, f.h)
	})
}

// A command-execution extension osctrld reports as kept while the node has
// no unexpired assignment for it is lingering, for environment and super
// admins alike. A stale ok sent after the removal is not.
func TestNodeExtensionsLingering(t *testing.T) {
	f := setupAssignHandlers(t)
	require.NoError(t, f.mgr.AssignEnv(f.envA.ID, f.osq.ID, "alice"))
	_, err := f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, nil, "root")
	require.NoError(t, err)
	at := time.Now().UTC().Truncate(time.Second)
	report := func(name, result, msg string) {
		require.NoError(t, f.mgr.RecordStatus("NODE-A", f.envA.ID, []types.OsctrldExtensionStatus{
			{Name: name, SHA256: strings.Repeat("a", 64), Result: result, Error: msg, At: at},
		}, at))
	}
	byName := func(got types.NodeExtensionsResponse) map[string]types.NodeExtensionStatusView {
		out := map[string]types.NodeExtensionStatusView{}
		for _, s := range got.Status {
			out[s.Name] = s
		}
		return out
	}
	lingering := func(user string) bool {
		return byName(nodeExts(t, f, user))["cmd"].Lingering
	}
	report("cmd", "ok", "")
	report("osq", "ok", "")
	require.False(t, lingering("alice"), "assigned")

	rr := extReq(t, f.h, callNodeExt(http.MethodDelete, f.envA.Name, "NODE-A", f.cmd.ID), "root", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	_, ok := byName(nodeExts(t, f, "alice"))["cmd"]
	require.False(t, ok, "the removed assignment's status went with it")

	// osctrld queued ok before the removal and sends it on the next request
	report("cmd", "ok", "")
	require.False(t, lingering("alice"), "a stale ok after unassigning")

	report("cmd", "kept", "osqueryd was not running 60s after the extension was removed")
	report("osq", "kept", "x")
	for _, user := range []string{"alice", "root"} {
		got := byName(nodeExts(t, f, user))
		require.True(t, got["cmd"].Lingering, user)
		require.Equal(t, "kept", got["cmd"].Result, user)
		require.False(t, got["osq"].Lingering, "ordinary extensions never linger")
	}

	// The evidence cannot be erased by deleting the extension
	rr = extReq(t, f.h, callDelete(f.cmd.ID), "root", nil, "")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())

	report("cmd", "removed", "")
	require.False(t, lingering("alice"), "removed after kept")

	// Kept with an expired assignment: still on the host, so lingering
	past := time.Now().Add(-time.Hour)
	_, err = f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, &past, "root")
	require.NoError(t, err)
	report("cmd", "kept", "cannot move")
	require.True(t, lingering("alice"), "kept with an expired assignment")

	// Removing the expired assignment keeps the evidence
	rr = extReq(t, f.h, callNodeExt(http.MethodDelete, f.envA.Name, "NODE-A", f.cmd.ID), "root", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.True(t, lingering("alice"), "kept survives removing the expired assignment")

	// Nor can it be hidden by turning command execution off
	rr = extReq(t, f.h, callUpdate(f.cmd.ID), "root", strings.NewReader(`{"command_execution":false}`), "application/json")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	require.True(t, lingering("alice"))

	// Kept with an unexpired assignment: it is meant to be there
	future := time.Now().Add(time.Hour)
	_, err = f.mgr.AssignNode("NODE-A", f.envA.ID, f.cmd.ID, &future, "root")
	require.NoError(t, err)
	require.False(t, lingering("alice"), "kept with an unexpired assignment")
}
