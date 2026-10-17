package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type extFixture struct {
	h      *HandlersTLS
	m      *extensions.Manager
	env    environments.TLSEnvironment
	envExt *extensions.Extension // ordinary, assigned to env
	envFile,
	nodeFile, // command-execution, assigned to nfNodeA in env
	otherFile *extensions.ExtensionFile // ordinary, assigned to the other environment
	envData []byte
}

func newExtFixture(t *testing.T) *extFixture {
	t.Helper()
	// Shared-cache named DB: every pooled connection sees the same data.
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{TranslateError: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	env := environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "env", Secret: "osctrld-test-secret", Hostname: "osctrl.example"}
	other := environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "other", Secret: "other-secret", Hostname: "osctrl.example"}
	require.NoError(t, db.Create(&env).Error)
	require.NoError(t, db.Create(&other).Error)
	for _, n := range []nodes.OsqueryNode{
		{NodeKey: "key-a", UUID: nfNodeA, EnvironmentID: env.ID},
		{NodeKey: "key-other", UUID: nfNodeOther, EnvironmentID: other.ID},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	m, err := extensions.NewManager(db)
	require.NoError(t, err)

	f := &extFixture{m: m, env: env, envData: bytes.Repeat([]byte("osquery-extension"), extensions.ChunkSize/8)}
	put := func(name string, cmdExec bool, data []byte) (*extensions.Extension, *extensions.ExtensionFile) {
		e, err := m.Create(extensions.Extension{Name: name, CommandExecution: cmdExec, CreatedBy: "admin"})
		require.NoError(t, err)
		file, err := m.PutFile(context.Background(), e.ID, "linux", "amd64", name+".ext", bytes.NewReader(data), "admin")
		require.NoError(t, err)
		return e, file
	}
	f.envExt, f.envFile = put("envext", false, f.envData)
	require.NoError(t, m.AssignEnv(env.ID, f.envExt.ID, "admin"))
	nodeExt, nodeFile := put("cmdext", true, []byte("command execution"))
	f.nodeFile = nodeFile
	_, err = m.AssignNode(nfNodeA, env.ID, nodeExt.ID, nil, "admin")
	require.NoError(t, err)
	// An assignment stored for the foreign node in this environment must not
	// be reachable by naming that node against this environment.
	_, err = m.AssignNode(nfNodeOther, env.ID, nodeExt.ID, nil, "admin")
	require.NoError(t, err)
	otherExt, otherFile := put("otherext", false, []byte("other environment"))
	f.otherFile = otherFile
	require.NoError(t, m.AssignEnv(other.ID, otherExt.ID, "admin"))

	f.h = CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesRepo), WithExtensions(m))
	return f
}

func extPost(h http.HandlerFunc, env environments.TLSEnvironment, req any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/osctrld", bytes.NewReader(body))
	r.SetPathValue("env", env.UUID)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func (f *extFixture) list(t *testing.T, req types.OsctrldExtensionsRequest) []types.OsctrldExtensionEntry {
	t.Helper()
	w := extPost(f.h.ExtensionsHandler, f.env, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var out []types.OsctrldExtensionEntry
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	return out
}

func (f *extFixture) entry(name string, file *extensions.ExtensionFile) types.OsctrldExtensionEntry {
	return types.OsctrldExtensionEntry{Name: name, SHA256: file.SHA256, Size: file.Size, URL: "/" + f.env.UUID + "/osctrld-extension"}
}

func (f *extFixture) statuses(t *testing.T, uuid string) []extensions.NodeExtensionStatus {
	t.Helper()
	st, err := f.m.NodeStatuses(uuid)
	require.NoError(t, err)
	return st
}

func (f *extFixture) req(uuid string, status ...types.OsctrldExtensionStatus) types.OsctrldExtensionsRequest {
	return types.OsctrldExtensionsRequest{Secret: f.env.Secret, UUID: uuid, Platform: "linux", Arch: "amd64", Status: status}
}

func TestExtensionsListEnvAndNode(t *testing.T) {
	f := newExtFixture(t)
	envOnly := []types.OsctrldExtensionEntry{f.entry("envext", f.envFile)}
	require.Equal(t, envOnly, f.list(t, f.req("")))
	both := []types.OsctrldExtensionEntry{f.entry("cmdext", f.nodeFile), f.entry("envext", f.envFile)}
	require.Equal(t, both, f.list(t, f.req(nfNodeA)))
	// osquery reports UUIDs in either case; the lookup must still match.
	require.Equal(t, both, f.list(t, f.req(strings.ToLower(nfNodeA))))
}

func TestExtensionsListUnknownOrForeignUUID(t *testing.T) {
	f := newExtFixture(t)
	st := types.OsctrldExtensionStatus{Name: "envext", SHA256: f.envFile.SHA256, Result: "ok", At: time.Now()}
	envOnly := []types.OsctrldExtensionEntry{f.entry("envext", f.envFile)}
	for _, uuid := range []string{nfNodeOther, nfUnknown, "not-a-uuid"} {
		require.Equal(t, envOnly, f.list(t, f.req(uuid, st)), uuid)
		require.Empty(t, f.statuses(t, uuid), uuid)
		require.Empty(t, f.statuses(t, strings.ToUpper(uuid)), uuid)
	}
}

func TestExtensionsListBadPlatform(t *testing.T) {
	f := newExtFixture(t)
	for _, pa := range [][2]string{{"plan9", "amd64"}, {"linux", "universal"}, {"windows", "arm64"}, {"", "amd64"}, {"linux", ""}, {"Linux", "amd64"}} {
		req := f.req(nfNodeA)
		req.Platform, req.Arch = pa[0], pa[1]
		w := extPost(f.h.ExtensionsHandler, f.env, req)
		require.Equal(t, http.StatusBadRequest, w.Code, pa)
	}
}

func TestExtensionsListWrongSecret(t *testing.T) {
	f := newExtFixture(t)
	req := f.req(nfNodeA, types.OsctrldExtensionStatus{Name: "envext", SHA256: f.envFile.SHA256, Result: "ok", At: time.Now()})
	for _, secret := range []string{"", "wrong", "other-secret"} {
		req.Secret = secret
		w := extPost(f.h.ExtensionsHandler, f.env, req)
		require.Equal(t, http.StatusForbidden, w.Code, secret)
		require.NotContains(t, w.Body.String(), f.envFile.SHA256)
	}
	require.Empty(t, f.statuses(t, nfNodeA))
}

func TestExtensionsListRecordsValidStatusOnly(t *testing.T) {
	f := newExtFixture(t)
	at := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	f.list(t, f.req(strings.ToLower(nfNodeA),
		types.OsctrldExtensionStatus{Name: "envext", SHA256: f.envFile.SHA256, Result: "rejected", Error: "bad signature", At: at},
		types.OsctrldExtensionStatus{Name: "cmdext", SHA256: f.nodeFile.SHA256, Result: "maybe", At: at},
		types.OsctrldExtensionStatus{Name: "otherext", SHA256: "not-a-sha", Result: "ok", At: at},
		types.OsctrldExtensionStatus{Name: "unknown", SHA256: f.envFile.SHA256, Result: "ok", At: at},
		types.OsctrldExtensionStatus{Name: "../evil", SHA256: f.envFile.SHA256, Result: "ok", At: at},
	))
	// Stored under the node row's upper-case UUID, not the request value.
	require.Empty(t, f.statuses(t, strings.ToLower(nfNodeA)))
	st := f.statuses(t, nfNodeA)
	require.Len(t, st, 1)
	require.Equal(t, "envext", st[0].Name)
	require.Equal(t, f.env.ID, st[0].EnvironmentID)
	require.Equal(t, "rejected", st[0].Result)
	require.Equal(t, "bad signature", st[0].Error)
	require.NotNil(t, st[0].At)
	require.True(t, at.Equal(*st[0].At))
}

func (f *extFixture) download(sha, secret string) *httptest.ResponseRecorder {
	return extPost(f.h.ExtensionDownloadHandler, f.env, types.OsctrldDownloadRequest{Secret: secret, SHA256: sha})
}

func TestExtensionDownloadStreams(t *testing.T) {
	f := newExtFixture(t)
	require.Greater(t, len(f.envData), extensions.ChunkSize, "payload must span chunks")
	w := f.download(f.envFile.SHA256, f.env.Secret)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
	require.Equal(t, strconv.Itoa(len(f.envData)), w.Header().Get("Content-Length"))
	require.True(t, bytes.Equal(f.envData, w.Body.Bytes()))
	// A node-assigned command-execution file is downloadable in its environment.
	w = f.download(f.nodeFile.SHA256, f.env.Secret)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "command execution", w.Body.String())
}

func TestExtensionDownloadNotInEnv(t *testing.T) {
	f := newExtFixture(t)
	for _, sha := range []string{f.otherFile.SHA256, strings.Repeat("a", 64)} {
		w := f.download(sha, f.env.Secret)
		require.Equal(t, http.StatusNotFound, w.Code, sha)
		require.Empty(t, w.Header().Get("Content-Length"))
	}
}

func TestExtensionDownloadReplacedFile(t *testing.T) {
	f := newExtFixture(t)
	old := f.envFile.SHA256
	nf, err := f.m.PutFile(context.Background(), f.envExt.ID, "linux", "amd64", "v2.ext", strings.NewReader("version two"), "admin")
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, f.download(old, f.env.Secret).Code)
	w := f.download(nf.SHA256, f.env.Secret)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "version two", w.Body.String())
}

func TestExtensionDownloadBadSHA(t *testing.T) {
	f := newExtFixture(t)
	for _, sha := range []string{"", "abc", strings.ToUpper(f.envFile.SHA256), f.envFile.SHA256 + "0", "../" + f.envFile.SHA256[3:], strings.Repeat("g", 64)} {
		require.Equal(t, http.StatusBadRequest, f.download(sha, f.env.Secret).Code, sha)
	}
}

func TestExtensionDownloadWrongSecret(t *testing.T) {
	f := newExtFixture(t)
	for _, secret := range []string{"", "wrong", "other-secret"} {
		w := f.download(f.envFile.SHA256, secret)
		require.Equal(t, http.StatusForbidden, w.Code, secret)
		require.Empty(t, w.Header().Get("Content-Length"))
		require.NotContains(t, w.Body.String(), "osquery-extension")
	}
}

// goneWriter is a client that disconnects after the first chunk.
type goneWriter struct {
	header http.Header
	writes int
}

func (g *goneWriter) Header() http.Header { return g.header }
func (g *goneWriter) WriteHeader(int)     {}
func (g *goneWriter) Write(b []byte) (int, error) {
	g.writes++
	if g.writes > 1 {
		return 0, errors.New("broken pipe")
	}
	return len(b), nil
}

func TestExtensionDownloadClientGone(t *testing.T) {
	f := newExtFixture(t)
	body, _ := json.Marshal(types.OsctrldDownloadRequest{Secret: f.env.Secret, SHA256: f.envFile.SHA256})
	r := httptest.NewRequest(http.MethodPost, "/osctrld", bytes.NewReader(body))
	r.SetPathValue("env", f.env.UUID)
	g := &goneWriter{header: http.Header{}}
	f.h.ExtensionDownloadHandler(g, r)
	require.Greater(t, len(f.envData), 2*extensions.ChunkSize, "payload must have a chunk left after the failure")
	require.Equal(t, 2, g.writes, "streaming must stop at the first failed write")
}

// An osctrld from before extensions sends neither platform nor arch: it gets
// an empty list, not an error every sync, and its status is not recorded.
func TestExtensionsListNoPlatform(t *testing.T) {
	f := newExtFixture(t)
	req := f.req(nfNodeA, types.OsctrldExtensionStatus{Name: "envext", SHA256: f.envFile.SHA256, Result: "ok", At: time.Now()})
	req.Platform, req.Arch = "", ""
	w := extPost(f.h.ExtensionsHandler, f.env, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.JSONEq(t, "[]", w.Body.String())
	require.Empty(t, f.statuses(t, nfNodeA))
}
