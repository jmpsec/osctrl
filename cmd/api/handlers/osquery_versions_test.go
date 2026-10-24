package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	oqDigest1 = "1111111111111111111111111111111111111111111111111111111111111111"
	oqDigest2 = "2222222222222222222222222222222222222222222222222222222222222222"
)

type oqFixture struct {
	h          *HandlersApi
	db         *gorm.DB
	envA, envB environments.TLSEnvironment
	mgr        *osqueryversions.Manager
	flags      *nodeconfig.FlagsManager
}

func setupOsqueryHandlers(t *testing.T) oqFixture {
	t.Helper()
	h, db, envA, envB, _ := setupNodeConfigHandlers(t)
	mgr, err := osqueryversions.NewManager(db)
	require.NoError(t, err)
	flags, err := nodeconfig.NewFlagsManager(db, nil)
	require.NoError(t, err)
	WithOsqueryVersions(mgr)(h)
	WithFlagsOverrides(flags)(h)
	return oqFixture{h: h, db: db, envA: envA, envB: envB, mgr: mgr, flags: flags}
}

func (f oqFixture) put(t *testing.T, version string) {
	t.Helper()
	require.NoError(t, f.mgr.PutEntries(version, []osqueryversions.DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: oqDigest1}}, "root"))
}

func oqCall(h *HandlersApi, hf func(*HandlersApi) http.HandlerFunc, method, user string, vals map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/x", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range vals {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
	rr := httptest.NewRecorder()
	hf(h)(rr, req)
	return rr
}

func libList(h *HandlersApi) http.HandlerFunc   { return h.OsqueryVersionsListHandler }
func libPut(h *HandlersApi) http.HandlerFunc    { return h.OsqueryVersionPutHandler }
func libDelete(h *HandlersApi) http.HandlerFunc { return h.OsqueryVersionDeleteHandler }
func envGet(h *HandlersApi) http.HandlerFunc    { return h.EnvOsqueryGetHandler }
func envPut(h *HandlersApi) http.HandlerFunc    { return h.EnvOsqueryPutHandler }
func envDel(h *HandlersApi) http.HandlerFunc    { return h.EnvOsqueryDeleteHandler }
func pinGet(h *HandlersApi) http.HandlerFunc    { return h.NodeOsqueryGetHandler }
func pinPut(h *HandlersApi) http.HandlerFunc    { return h.NodeOsqueryPutHandler }
func pinDel(h *HandlersApi) http.HandlerFunc    { return h.NodeOsqueryDeleteHandler }

const okEntries = `{"entries":[{"platform":"linux","arch":"amd64","format":"deb","sha256":"` + oqDigest1 + `"}]}`

func TestLibraryRequiresSuperAdmin(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.12.1")
	calls := []struct {
		hf     func(*HandlersApi) http.HandlerFunc
		method string
		body   string
	}{{libList, http.MethodGet, ""}, {libPut, http.MethodPut, okEntries}, {libDelete, http.MethodDelete, ""}}
	for _, user := range []string{"alice", "bob"} {
		for _, c := range calls {
			before := len(auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment))
			rr := oqCall(f.h, c.hf, c.method, user, map[string]string{"version": "5.12.1"}, c.body)
			require.Equal(t, http.StatusForbidden, rr.Code, "%s %s", user, c.method)
			lines := auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
			require.Len(t, lines, before+1)
			require.Contains(t, lines[len(lines)-1], "denied access for user "+user)
		}
	}
	got, err := f.mgr.GetEntries("5.12.1")
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func TestLibraryPutListAudit(t *testing.T) {
	f := setupOsqueryHandlers(t)
	rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, okEntries)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = oqCall(f.h, libList, http.MethodGet, "root", nil, "")
	require.Equal(t, http.StatusOK, rr.Code)
	var out []types.OsqueryVersionView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.Len(t, out, 1)
	require.Equal(t, "5.12.1", out[0].Version)
	require.False(t, out[0].InUse)
	require.Equal(t, oqDigest1, out[0].Entries[0].SHA256)
	require.Equal(t, "root", out[0].Entries[0].CreatedBy)
	lines := auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "5.12.1")
	require.Contains(t, lines[0], "linux/amd64/deb="+oqDigest1)
	require.NotContains(t, lines[0], "(was")
}

// A digest decides what runs as root on every host: the audit line records
// each entry written and the digest it replaced.
func TestLibraryPutAuditsReplacedDigest(t *testing.T) {
	f := setupOsqueryHandlers(t)
	require.NoError(t, f.mgr.PutEntries("5.12.1", []osqueryversions.DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: oqDigest1},
		{Platform: "linux", Arch: "amd64", Format: "rpm", SHA256: oqDigest1},
		{Platform: "darwin", Arch: "universal", Format: "pkg", SHA256: oqDigest1}}, "root"))
	body := `{"entries":[{"platform":"linux","arch":"amd64","format":"deb","sha256":"` + oqDigest2 + `"},` +
		`{"platform":"linux","arch":"amd64","format":"rpm","sha256":"` + oqDigest1 + `"},` +
		`{"platform":"linux","arch":"arm64","format":"deb","sha256":"` + oqDigest2 + `"}]}`
	rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, body)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	lines := auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "linux/amd64/deb="+oqDigest2+" (was "+oqDigest1+")")
	require.Contains(t, lines[0], "linux/amd64/rpm="+oqDigest1)
	require.NotContains(t, lines[0], "linux/amd64/rpm="+oqDigest1+" (was")
	require.Contains(t, lines[0], "linux/arm64/deb="+oqDigest2)
	require.NotContains(t, lines[0], "darwin", "untouched entries are not listed")
}

// The body holds at most the five supported combinations, each once, so the
// audit line lists exactly the entries written.
func TestLibraryPutRejectsDuplicateOrTooManyEntries(t *testing.T) {
	f := setupOsqueryHandlers(t)
	entry := func(platform, arch, format string) string {
		return `{"platform":"` + platform + `","arch":"` + arch + `","format":"` + format + `","sha256":"` + oqDigest1 + `"}`
	}
	all := []string{entry("linux", "amd64", "deb"), entry("linux", "arm64", "deb"), entry("linux", "amd64", "rpm"),
		entry("linux", "arm64", "rpm"), entry("darwin", "universal", "pkg")}
	for name, list := range map[string][]string{
		"duplicate": {all[0], all[0]},
		"six":       append(append([]string{}, all...), all[0]),
		"fifty":     strings.Split(strings.TrimSuffix(strings.Repeat(all[0]+"|", 50), "|"), "|"),
	} {
		rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, `{"entries":[`+strings.Join(list, ",")+`]}`)
		require.Equal(t, http.StatusBadRequest, rr.Code, name)
	}
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment))
	got, err := f.mgr.GetEntries("5.12.1")
	require.NoError(t, err)
	require.Empty(t, got)

	rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, `{"entries":[`+strings.Join(all, ",")+`]}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	lines := auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
	require.Len(t, lines, 1)
	require.Equal(t, 5, strings.Count(lines[0], oqDigest1))
}

// A misspelled field must not be ignored (a pin without its expiry never
// expires), and nothing may follow the JSON object.
func TestOsqueryPutsRejectUnknownFieldsAndTrailingData(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	puts := []struct {
		name       string
		hf         func(*HandlersApi) http.HandlerFunc
		user       string
		vals       map[string]string
		ok, typo   string
		logType    uint
		auditEnvID uint
	}{
		{"library", libPut, "root", map[string]string{"version": "5.14.0"}, okEntries,
			`{"entries":[{"platform":"linux","arch":"amd64","format":"deb","sha265":"` + oqDigest1 + `"}]}`, auditlog.LogTypeSetting, auditlog.NoEnvironment},
		{"env target", envPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"5.13.0"}`,
			`{"version":"5.13.0","target":"5.14.0"}`, auditlog.LogTypeEnvironment, f.envA.ID},
		{"pin", pinPut, "alice", nodeVals(f.envA, "NODE-A"), `{"version":"5.13.0"}`,
			`{"version":"5.13.0","expires":"2030-01-01T00:00:00Z"}`, auditlog.LogTypeNode, f.envA.ID},
	}
	for _, c := range puts {
		for name, body := range map[string]string{
			"unknown field":  c.typo,
			"trailing data":  c.ok + `{}`,
			"trailing token": c.ok + ` x`,
		} {
			rr := oqCall(f.h, c.hf, http.MethodPut, c.user, c.vals, body)
			require.Equal(t, http.StatusBadRequest, rr.Code, "%s %s", c.name, name)
			require.Contains(t, rr.Body.String(), "invalid request body", "%s %s", c.name, name)
		}
		require.Empty(t, auditLines(t, f.db, c.logType, c.auditEnvID), c.name)
		// trailing whitespace is fine
		require.Equal(t, http.StatusOK, oqCall(f.h, c.hf, http.MethodPut, c.user, c.vals, c.ok+"\n").Code, c.name)
	}
	p, err := f.mgr.GetPin("NODE-A")
	require.NoError(t, err)
	require.Nil(t, p.ExpiresAt)
}

func TestLibraryInvalidVersionPathIs400(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for _, v := range []string{"evil", "5", "5.x", "../5.12.1", ""} {
		rr := oqCall(f.h, libDelete, http.MethodDelete, "root", map[string]string{"version": v}, "")
		require.Equal(t, http.StatusBadRequest, rr.Code, v)
		rr = oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": v}, okEntries)
		require.Equal(t, http.StatusBadRequest, rr.Code, v)
	}
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment))
}

// Clearing what is not set answers 200 (idempotent) without claiming a change.
func TestOsqueryDeletesOfNothingAreNotAudited(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envDel, http.MethodDelete, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
	rr = oqCall(f.h, pinDel, http.MethodDelete, "alice", nodeVals(f.envA, "NODE-A"), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeNode, f.envA.ID))
}

// Only a missing version is a 404; a database error is a 500.
func TestOsqueryDatabaseErrorsAre500(t *testing.T) {
	// Each table with the calls that read it (no pin and no target is set).
	for table, names := range map[string][]string{
		"osquery_package_digests": {"env get", "node get", "node put", "library list", "library put", "library delete"},
		"osquery_env_targets":     {"env get", "node get", "library list", "library put", "library delete"},
		"osquery_node_pins":       {"node get", "node put", "library list", "library put", "library delete"},
	} {
		t.Run(table, func(t *testing.T) {
			f := setupOsqueryHandlers(t)
			f.put(t, "5.13.0")
			calls := map[string]func() *httptest.ResponseRecorder{
				"env get": func() *httptest.ResponseRecorder {
					return oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
				},
				"node get": func() *httptest.ResponseRecorder {
					return oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "")
				},
				"node put": func() *httptest.ResponseRecorder {
					return oqCall(f.h, pinPut, http.MethodPut, "alice", nodeVals(f.envA, "NODE-A"), `{"version":"5.13.0"}`)
				},
				"library list": func() *httptest.ResponseRecorder { return oqCall(f.h, libList, http.MethodGet, "root", nil, "") },
				"library put": func() *httptest.ResponseRecorder {
					return oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.13.0"}, okEntries)
				},
				"library delete": func() *httptest.ResponseRecorder {
					return oqCall(f.h, libDelete, http.MethodDelete, "root", map[string]string{"version": "5.13.0"}, "")
				},
			}
			require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("oqfail", func(tx *gorm.DB) {
				if tx.Statement.Table == table {
					_ = tx.AddError(errors.New("injected db error"))
				}
			}))
			for _, name := range names {
				rr := calls[name]()
				require.Equal(t, http.StatusInternalServerError, rr.Code, "%s: %s", name, rr.Body.String())
			}
		})
	}
}

func TestLibraryPutValidatesEntries(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for name, body := range map[string]string{
		"windows": `{"entries":[{"platform":"windows","arch":"386","format":"msi","sha256":"` + oqDigest1 + `"}]}`,
		"digest":  `{"entries":[{"platform":"linux","arch":"amd64","format":"deb","sha256":"ABC"}]}`,
		"empty":   `{"entries":[]}`,
		"json":    `{`,
	} {
		rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, body)
		require.Equal(t, http.StatusBadRequest, rr.Code, name)
	}
	rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "evil"}, okEntries)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment))
}

func TestLibraryPutAcceptsWindowsMSI(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for arch, want := range map[string]int{"amd64": http.StatusOK, "arm64": http.StatusBadRequest} {
		body := `{"entries":[{"platform":"windows","arch":"` + arch + `","format":"msi","sha256":"` + oqDigest1 + `"}]}`
		rr := oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, body)
		require.Equal(t, want, rr.Code, arch+rr.Body.String())
	}
}

func TestLibraryDeleteInUseIs409(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.12.1")
	_, err := f.mgr.SetEnvTarget(f.envA.ID, "5.12.1", "alice")
	require.NoError(t, err)
	rr := oqCall(f.h, libDelete, http.MethodDelete, "root", map[string]string{"version": "5.12.1"}, "")
	require.Equal(t, http.StatusConflict, rr.Code)
	// changing a digest of an in-use version is also a conflict
	body := `{"entries":[{"platform":"linux","arch":"amd64","format":"deb","sha256":"` + oqDigest2 + `"}]}`
	rr = oqCall(f.h, libPut, http.MethodPut, "root", map[string]string{"version": "5.12.1"}, body)
	require.Equal(t, http.StatusConflict, rr.Code)
	rr = oqCall(f.h, libList, http.MethodGet, "root", nil, "")
	require.Contains(t, rr.Body.String(), `"in_use":true`)

	_, err = f.mgr.ClearEnvTarget(f.envA.ID)
	require.NoError(t, err)
	rr = oqCall(f.h, libDelete, http.MethodDelete, "root", map[string]string{"version": "5.12.1"}, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = oqCall(f.h, libDelete, http.MethodDelete, "root", map[string]string{"version": "5.12.1"}, "")
	require.Equal(t, http.StatusNotFound, rr.Code)
	lines := auditLines(t, f.db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
	require.Len(t, lines, 1, "only the successful delete is audited")
	require.Contains(t, lines[0], "linux/amd64/deb="+oqDigest1, "the removed entries are listed")
}

func TestEnvTargetRequiresEnvAdmin(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	vals := map[string]string{"env": f.envA.Name}
	for _, c := range []struct {
		hf     func(*HandlersApi) http.HandlerFunc
		method string
	}{{envGet, http.MethodGet}, {envPut, http.MethodPut}, {envDel, http.MethodDelete}} {
		rr := oqCall(f.h, c.hf, c.method, "bob", vals, `{"version":"5.13.0"}`)
		require.Equal(t, http.StatusForbidden, rr.Code, c.method)
	}
	require.Len(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID), 3)
	tgt, err := f.mgr.GetEnvTarget(f.envA.ID)
	require.NoError(t, err)
	require.Nil(t, tgt)

	rr := oqCall(f.h, envPut, http.MethodPut, "alice", vals, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.EnvOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.Equal(t, "5.13.0", out.Target.Version)
	require.Equal(t, "alice", out.Target.UpdatedBy)
	require.NotEmpty(t, out.Target.RequestID)
	rr = oqCall(f.h, envDel, http.MethodDelete, "alice", vals, "")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"target":null`)
	require.Len(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID), 5, "one row per mutation")
}

func TestEnvTargetScopedToEnvironment(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envB.Name}, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusForbidden, rr.Code)
	tgt, err := f.mgr.GetEnvTarget(f.envB.ID)
	require.NoError(t, err)
	require.Nil(t, tgt)
	// counts only cover the caller's environment
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("osquery_version", "5.12.1").Error)
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-B").Update("osquery_version", "5.11.0").Error)
	rr = oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusOK, rr.Code)
	var out types.EnvOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.Nil(t, out.Target)
	require.Equal(t, []types.OsqueryVersionHostCount{{Version: "5.12.1", Count: 1}}, out.Counts)
}

func TestEnvTargetUnknownVersionIs400(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for _, v := range []string{"9.9.9", "bad", ""} {
		rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"`+v+`"}`)
		require.Equal(t, http.StatusBadRequest, rr.Code, v)
	}
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
}

func nodeVals(env environments.TLSEnvironment, uuid string) map[string]string {
	return map[string]string{"env": env.Name, "uuid": uuid}
}

func TestPinUsesNodeConfigTargetGuard(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	body := `{"version":"5.13.0"}`
	for _, c := range []struct {
		hf     func(*HandlersApi) http.HandlerFunc
		method string
	}{{pinGet, http.MethodGet}, {pinPut, http.MethodPut}, {pinDel, http.MethodDelete}} {
		before := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
		require.Equal(t, http.StatusForbidden, oqCall(f.h, c.hf, c.method, "bob", nodeVals(f.envA, "NODE-A"), body).Code)
		lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
		require.Len(t, lines, before+1, c.method)
		require.Contains(t, lines[len(lines)-1], "denied access for user bob", c.method)
		beforeB := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envB.ID))
		// alice administers a, not b
		require.Equal(t, http.StatusForbidden, oqCall(f.h, c.hf, c.method, "alice", nodeVals(f.envB, "NODE-B"), body).Code)
		linesB := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envB.ID)
		require.Len(t, linesB, beforeB+1, c.method)
		require.Contains(t, linesB[len(linesB)-1], "denied access for user alice", c.method)
		// a node of another environment looked up through env a
		require.Equal(t, http.StatusNotFound, oqCall(f.h, c.hf, c.method, "alice", nodeVals(f.envA, "NODE-B"), body).Code)
	}
	p, err := f.mgr.GetPin("NODE-B")
	require.NoError(t, err)
	require.Nil(t, p)
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeNode, f.envA.ID))
}

func TestPinPastExpiryIs400(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	rr := oqCall(f.h, pinPut, http.MethodPut, "alice", nodeVals(f.envA, "NODE-A"), `{"version":"5.13.0","expires_at":"`+past+`"}`)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	rr = oqCall(f.h, pinPut, http.MethodPut, "alice", nodeVals(f.envA, "NODE-A"), `{"version":"9.9.9"}`)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	p, err := f.mgr.GetPin("NODE-A")
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestNodeOsqueryGetShowsResolveReasonAndUpgradeState(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	f.put(t, "5.14.0")
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("osquery_version", "5.12.1").Error)
	vals := nodeVals(f.envA, "NODE-A")
	get := func() types.NodeOsqueryResponse {
		rr := oqCall(f.h, pinGet, http.MethodGet, "alice", vals, "")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var out types.NodeOsqueryResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		return out
	}
	out := get()
	require.Nil(t, out.Pin)
	require.Nil(t, out.Target)
	require.Nil(t, out.Upgrade)
	require.Equal(t, "5.12.1", out.InstalledVersion)

	_, err := f.mgr.SetEnvTarget(f.envA.ID, "5.13.0", "alice")
	require.NoError(t, err)
	out = get()
	require.Equal(t, &types.OsqueryEffectiveTarget{Version: "5.13.0", Source: "environment"}, out.Target)

	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	rr := oqCall(f.h, pinPut, http.MethodPut, "alice", vals, `{"version":"5.14.0","expires_at":"`+exp.Format(time.RFC3339)+`"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out = get()
	require.Equal(t, "5.14.0", out.Pin.Version)
	require.Equal(t, "alice", out.Pin.UpdatedBy)
	require.True(t, exp.Equal(*out.Pin.ExpiresAt))
	require.Equal(t, &types.OsqueryEffectiveTarget{Version: "5.14.0", Source: "pin"}, out.Target)

	// an expired pin no longer wins
	require.NoError(t, f.db.Model(&osqueryversions.NodePin{}).Where("node_uuid = ?", "NODE-A").Update("expires_at", time.Now().Add(-time.Minute)).Error)
	require.Equal(t, "environment", get().Target.Source)

	// stored upgrade report
	_, err = f.flags.RecordReport("NODE-A", f.envA.ID, types.OsctrldStatusRequest{
		Upgrade: &types.OsctrldUpgrade{Result: "skipped", Version: "5.13.0", Reason: "digest_mismatch", RequestID: "3f2a3f2a3f2a3f2a3f2a3f2a3f2a3f2a"}}, time.Now())
	require.NoError(t, err)
	out = get()
	require.Equal(t, "skipped", out.Upgrade.Result)
	require.Equal(t, "digest_mismatch", out.Upgrade.Reason)
	require.Equal(t, "5.13.0", out.Upgrade.Version)
	require.Equal(t, "3f2a3f2a3f2a3f2a3f2a3f2a3f2a3f2a", out.Upgrade.RequestID)
	require.False(t, out.Upgrade.ReportedAt.IsZero())
}

// A pin set through the API is keyed by the node row's upper-case UUID, so the
// TLS Resolve (which uses node.UUID) applies it and CountBehind counts it.
func TestPinAppliedByResolveAndCountBehind(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.12.1")
	f.put(t, "5.14.0")
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("osquery_version", "5.12.1").Error)
	_, err := f.mgr.SetEnvTarget(f.envA.ID, "5.12.1", "alice")
	require.NoError(t, err)
	_, err = f.flags.RecordReport("NODE-A", f.envA.ID, types.OsctrldStatusRequest{}, time.Now())
	require.NoError(t, err)
	rr := oqCall(f.h, pinPut, http.MethodPut, "alice", nodeVals(f.envA, "NODE-A"), `{"version":"5.14.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	res, err := f.mgr.Resolve(osqueryversions.ResolveInput{EnvironmentID: f.envA.ID, NodeUUID: "NODE-A",
		Platform: "linux", Arch: "amd64", Format: "deb", InstalledVersion: "5.12.1"}, time.Now())
	require.NoError(t, err)
	require.Equal(t, "pin", res.Source)
	behind, err := f.mgr.CountBehind(time.Now(), time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, behind[f.envA.ID])
}

func TestNodeOsqueryPinDeleteAudited(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	vals := nodeVals(f.envA, "NODE-A")
	require.Equal(t, http.StatusOK, oqCall(f.h, pinPut, http.MethodPut, "alice", vals, `{"version":"5.13.0"}`).Code)
	rr := oqCall(f.h, pinDel, http.MethodDelete, "alice", vals, "")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"pin":null`)
	lines := auditLines(t, f.db, auditlog.LogTypeNode, f.envA.ID)
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "NODE-A")
}

func TestNodeDeletionRemovesPin(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	_, err := f.mgr.SetPin("NODE-A", f.envA.ID, "5.13.0", nil, "alice")
	require.NoError(t, err)
	WithNodes(nodes.CreateNodes(f.db))(f.h)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/a/delete", strings.NewReader(`{"uuid":"NODE-A"}`))
	req.RemoteAddr = "127.0.0.1:1234"
	req.SetPathValue("env", f.envA.Name)
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: "alice"}))
	rr := httptest.NewRecorder()
	f.h.DeleteNodeHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	p, err := f.mgr.GetPin("NODE-A")
	require.NoError(t, err)
	require.Nil(t, p)
}

func TestEnvOsqueryGetListsAvailableVersionsForEnvAdmin(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.12.1")
	f.put(t, "5.9.0")
	rr := oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.EnvOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.Equal(t, []string{"5.9.0", "5.12.1"}, out.Available)
	require.NotContains(t, rr.Body.String(), oqDigest1)
	require.NotContains(t, rr.Body.String(), "created_by")
	require.Equal(t, http.StatusForbidden, oqCall(f.h, envGet, http.MethodGet, "bob", map[string]string{"env": f.envA.Name}, "").Code)
}

func TestNodeOsqueryGetListsAvailableVersions(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	rr := oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.NodeOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	require.Equal(t, []string{"5.13.0"}, out.Available)
	require.NotContains(t, rr.Body.String(), oqDigest1)
}

func TestAvailableVersionsSortedNumerically(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for _, v := range []string{"5.12.1", "5.9.0", "5.10.0"} {
		f.put(t, v)
	}
	names, err := f.mgr.VersionNames()
	require.NoError(t, err)
	require.Equal(t, []string{"5.9.0", "5.10.0", "5.12.1"}, names)
}

func TestAvailableIsEmptyArrayNotNull(t *testing.T) {
	f := setupOsqueryHandlers(t)
	rr := oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Contains(t, rr.Body.String(), `"available":[]`)
	rr = oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "")
	require.Contains(t, rr.Body.String(), `"available":[]`)
}

// Windows is upgraded like other platforms; only platforms without a package are flagged.
func TestNodeOsqueryWindowsNotUnsupported(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for platform, want := range map[string]bool{"freebsd": true, "windows": false, "Windows": false, "darwin": false, "ubuntu": false, "": false} {
		require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", platform).Error)
		rr := oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var out types.NodeOsqueryResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		require.Equal(t, want, out.PlatformUnsupported, platform)
		require.Contains(t, rr.Body.String(), `"platform_unsupported":`)
	}
}

// The trailing-data check keeps a too-large body a 413.
func TestOsqueryPutTrailingDataLimits(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	vals := nodeVals(f.envA, "NODE-A")
	body := `{"version":"5.13.0"}`
	require.Equal(t, http.StatusRequestEntityTooLarge, oqCall(f.h, pinPut, http.MethodPut, "alice", vals, body+strings.Repeat(" ", 100<<10)).Code)
	require.Equal(t, http.StatusBadRequest, oqCall(f.h, pinPut, http.MethodPut, "alice", vals, body+`{}`).Code)
	require.Equal(t, http.StatusOK, oqCall(f.h, pinPut, http.MethodPut, "alice", vals, body+"\n").Code)
}

// Environment targets do not expire: an expires_at must not be silently dropped.
func TestEnvTargetRejectsExpiry(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"5.13.0","expires_at":"2030-01-01T00:00:00Z"}`)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "environment targets do not expire")
	tgt, err := f.mgr.GetEnvTarget(f.envA.ID)
	require.NoError(t, err)
	require.Nil(t, tgt)
	require.Empty(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
}

func rolloutResume(h *HandlersApi) http.HandlerFunc { return h.EnvOsqueryRolloutResumeHandler }
func rolloutAbort(h *HandlersApi) http.HandlerFunc  { return h.EnvOsqueryRolloutAbortHandler }

func decodeEnvOsquery(t *testing.T, rr *httptest.ResponseRecorder) types.EnvOsqueryResponse {
	t.Helper()
	var out types.EnvOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out), rr.Body.String())
	return out
}

func TestEnvTargetPutStartsRollout(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	vals := map[string]string{"env": f.envA.Name}
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", vals, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.NotNil(t, out.Rollout)
	require.Equal(t, "running", out.Rollout.State)
	require.Equal(t, 1, out.Rollout.Stage)
	require.Equal(t, []int{1, 10, 50, 100}, out.Rollout.Stages)
	require.Equal(t, "5.13.0", out.Rollout.Version)
	require.Equal(t, out.Target.RequestID, out.Rollout.RequestID)
	require.NotNil(t, out.Rollout.NextStageAt)
	require.Nil(t, out.Rollout.Paused)
	require.Equal(t, 1, out.Rollout.Counts.Eligible)
	require.Equal(t, 1, out.Rollout.Counts.Waiting)
	require.Contains(t, rr.Body.String(), `"rolled_back_hosts":[]`)
	lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "rollout starts at stage 1")
}

func TestEnvTargetPutReplacesRolloutAndAbortsOld(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.13.0")
	f.put(t, "5.14.0")
	vals := map[string]string{"env": f.envA.Name}
	first := decodeEnvOsquery(t, oqCall(f.h, envPut, http.MethodPut, "alice", vals, `{"version":"5.13.0"}`))
	second := decodeEnvOsquery(t, oqCall(f.h, envPut, http.MethodPut, "alice", vals, `{"version":"5.14.0"}`))
	require.NotEqual(t, first.Rollout.RequestID, second.Rollout.RequestID)
	require.Equal(t, "running", second.Rollout.State)
	var old osqueryversions.Rollout
	require.NoError(t, f.db.Where("request_id = ?", first.Rollout.RequestID).First(&old).Error)
	require.Equal(t, osqueryversions.RolloutAborted, old.State)
}

func TestEnvOsqueryGetNullRolloutWhenNone(t *testing.T) {
	f := setupOsqueryHandlers(t)
	rr := oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Body.String(), `"rollout":null`)
}

func startRollout(t *testing.T, f oqFixture) types.EnvOsqueryResponse {
	t.Helper()
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	return decodeEnvOsquery(t, rr)
}

func TestRolloutResumeOnlyWhenPaused(t *testing.T) {
	f := setupOsqueryHandlers(t)
	vals := map[string]string{"env": f.envA.Name}
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "").Code, "no rollout")
	st := startRollout(t, f)
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "").Code, "running")
	ok, err := f.mgr.PauseRollout(f.envA.ID, st.Rollout.RequestID, "web-1", "version_not_reported", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	rr := oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.Equal(t, "running", out.Rollout.State)
	require.Nil(t, out.Rollout.Paused)
	lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
	require.Len(t, lines, 2)
	require.Contains(t, lines[1], "resumed")
	// aborted and completed answer 409 too
	require.Equal(t, http.StatusOK, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "").Code)
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "").Code, "aborted")
	startRollout(t, f)
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ? AND state = ?", f.envA.ID, "running").
		Update("stage_opened_at", time.Now().Add(-7*time.Hour)).Error)
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutResume, http.MethodPost, "alice", vals, "").Code, "completed")
}

func TestRolloutAbortFromRunningAndPaused(t *testing.T) {
	f := setupOsqueryHandlers(t)
	vals := map[string]string{"env": f.envA.Name}
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "").Code, "none")
	startRollout(t, f)
	_, err := f.mgr.SetPin("NODE-A", f.envA.ID, "5.13.0", nil, "alice")
	require.NoError(t, err)
	rr := oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.Nil(t, out.Target)
	require.Equal(t, "aborted", out.Rollout.State)
	pin, err := f.mgr.GetPin("NODE-A")
	require.NoError(t, err)
	require.NotNil(t, pin, "pins are kept")
	require.Equal(t, http.StatusConflict, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "").Code, "already aborted")

	st := startRollout(t, f)
	ok, err := f.mgr.PauseRollout(f.envA.ID, st.Rollout.RequestID, "web-1", "version_not_reported", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	out = decodeEnvOsquery(t, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, ""))
	require.Equal(t, "aborted", out.Rollout.State)
	lines := auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID)
	require.Contains(t, lines[len(lines)-1], "aborted")
}

func TestRolloutEndpointsRequireEnvAdminOfThatEnvironment(t *testing.T) {
	f := setupOsqueryHandlers(t)
	st := startRollout(t, f)
	ok, err := f.mgr.PauseRollout(f.envA.ID, st.Rollout.RequestID, "web-1", "version_not_reported", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	before := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
	vals := map[string]string{"env": f.envA.Name}
	for _, user := range []string{"bob"} {
		for _, hf := range []func(*HandlersApi) http.HandlerFunc{rolloutResume, rolloutAbort} {
			require.Equal(t, http.StatusForbidden, oqCall(f.h, hf, http.MethodPost, user, vals, "").Code)
		}
	}
	// alice administers env a only
	for _, hf := range []func(*HandlersApi) http.HandlerFunc{rolloutResume, rolloutAbort} {
		require.Equal(t, http.StatusForbidden, oqCall(f.h, hf, http.MethodPost, "alice", map[string]string{"env": f.envB.Name}, "").Code)
	}
	require.Len(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID), before+2, "denials audited")
	require.Len(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envB.ID), 2)
	r, err := f.mgr.GetRollout(f.envA.ID)
	require.NoError(t, err)
	require.Equal(t, osqueryversions.RolloutPaused, r.State)
	tgt, err := f.mgr.GetEnvTarget(f.envA.ID)
	require.NoError(t, err)
	require.NotNil(t, tgt)
}

func TestRolloutPausedViewShowsFirstRollback(t *testing.T) {
	f := setupOsqueryHandlers(t)
	st := startRollout(t, f)
	ok, err := f.mgr.PauseRollout(f.envA.ID, st.Rollout.RequestID, "web-1", "version_not_reported", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, f.db.Exec("UPDATE osquery_nodes SET hostname = 'web-1' WHERE uuid = 'NODE-A'").Error)
	now := time.Now()
	require.NoError(t, f.db.Create(&nodeconfig.OsctrldStatus{NodeUUID: "NODE-A", EnvironmentID: f.envA.ID,
		UpgradeResult: "rejected", UpgradeReason: "version_not_reported", UpgradeRequestID: st.Rollout.RequestID, UpgradeReportedAt: &now}).Error)
	rr := oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
	out := decodeEnvOsquery(t, rr)
	require.Equal(t, "paused", out.Rollout.State)
	require.NotNil(t, out.Rollout.Paused)
	require.Equal(t, "web-1", out.Rollout.Paused.Host)
	require.Equal(t, "version_not_reported", out.Rollout.Paused.Reason)
	require.Nil(t, out.Rollout.NextStageAt)
	require.Len(t, out.Rollout.RolledBackHosts, 1)
	require.Equal(t, 1, out.Rollout.Counts.RolledBack)
	require.Equal(t, "web-1", out.Rollout.RolledBackHosts[0].Host)
}

func TestEnvTargetDeleteAbortsRollout(t *testing.T) {
	f := setupOsqueryHandlers(t)
	startRollout(t, f)
	rr := oqCall(f.h, envDel, http.MethodDelete, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.Nil(t, out.Target)
	require.Equal(t, "aborted", out.Rollout.State)
}

func TestRolloutAbortOnCompletedIs409AndKeepsTarget(t *testing.T) {
	f := setupOsqueryHandlers(t)
	startRollout(t, f)
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).
		Update("stage_opened_at", time.Now().Add(-7*time.Hour)).Error)
	before := len(auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID))
	rr := oqCall(f.h, rolloutAbort, http.MethodPost, "alice", map[string]string{"env": f.envA.Name}, "")
	require.Equal(t, http.StatusConflict, rr.Code)
	tgt, err := f.mgr.GetEnvTarget(f.envA.ID)
	require.NoError(t, err)
	require.NotNil(t, tgt)
	require.Len(t, auditLines(t, f.db, auditlog.LogTypeEnvironment, f.envA.ID), before)
}

func TestRolloutNoRolloutIs409NoRollout(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for _, hf := range []func(*HandlersApi) http.HandlerFunc{rolloutResume, rolloutAbort} {
		rr := oqCall(f.h, hf, http.MethodPost, "alice", map[string]string{"env": f.envA.Name}, "")
		require.Equal(t, http.StatusConflict, rr.Code)
		require.Contains(t, rr.Body.String(), "no rollout")
	}
}

func TestEnvTargetPutWithZeroNodes(t *testing.T) {
	f := setupOsqueryHandlers(t)
	require.NoError(t, f.db.Where("environment_id = ?", f.envA.ID).Delete(&nodes.OsqueryNode{}).Error)
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.Equal(t, "running", out.Rollout.State)
	require.Equal(t, 1, out.Rollout.Stage)
	require.Equal(t, types.EnvOsqueryRolloutCounts{}, out.Rollout.Counts)
}

func TestRolloutViewOfAbortedRolloutSkipsHostScan(t *testing.T) {
	f := setupOsqueryHandlers(t)
	vals := map[string]string{"env": f.envA.Name}
	startRollout(t, f)
	require.Equal(t, http.StatusOK, oqCall(f.h, rolloutAbort, http.MethodPost, "alice", vals, "").Code)
	// Progress reads this table: dropping it proves the aborted view does not.
	require.NoError(t, f.db.Migrator().DropTable("node_osctrld_status"))
	rr := oqCall(f.h, envGet, http.MethodGet, "alice", vals, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	out := decodeEnvOsquery(t, rr)
	require.Equal(t, "aborted", out.Rollout.State)
	require.Equal(t, types.EnvOsqueryRolloutCounts{}, out.Rollout.Counts)
	require.Contains(t, rr.Body.String(), `"rolled_back_hosts":[]`)
}

// nodeRolloutFixture starts a rollout and places NODE-A in the given 0-based stage.
func nodeRolloutFixture(t *testing.T, f oqFixture, stage int) {
	t.Helper()
	startRollout(t, f)
	b := osqueryversions.Bucket(f.envA.ID, "5.13.0", "NODE-A")
	th := [4]uint32{b + 10, b + 20, b + 30, 10001}
	for i := 0; i < stage; i++ {
		th[i] = b // bucket < b never holds, so the node is not in stage i
	}
	raw, err := json.Marshal(th)
	require.NoError(t, err)
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("thresholds", string(raw)).Error)
}

func getNodeOsquery(t *testing.T, f oqFixture) types.NodeOsqueryResponse {
	t.Helper()
	rr := oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out types.NodeOsqueryResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func TestNodeOsqueryRolloutLaterStageHasEligibleAt(t *testing.T) {
	f := setupOsqueryHandlers(t)
	nodeRolloutFixture(t, f, 2) // node joins stage 3
	opened := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("stage_opened_at", opened).Error)
	out := getNodeOsquery(t, f)
	require.NotNil(t, out.Rollout)
	require.Equal(t, "running", out.Rollout.State)
	require.Equal(t, 3, out.Rollout.Stage)
	require.Equal(t, []int{1, 10, 50, 100}, out.Rollout.Stages)
	require.NotNil(t, out.Rollout.EligibleAt)
	require.True(t, opened.Add(2*osqueryversions.RolloutStageWait).Equal(*out.Rollout.EligibleAt))
	// stage 2 is open: stage 3 opens two hours after that
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("stage_opened_at", opened.Add(-2*time.Hour)).Error)
	out = getNodeOsquery(t, f)
	require.True(t, opened.Add(-2*time.Hour).Add(2*osqueryversions.RolloutStageWait).Equal(*out.Rollout.EligibleAt))
}

func TestNodeOsqueryRolloutOpenStageHasNoEligibleAt(t *testing.T) {
	f := setupOsqueryHandlers(t)
	nodeRolloutFixture(t, f, 0)
	out := getNodeOsquery(t, f)
	require.NotNil(t, out.Rollout)
	require.Equal(t, 1, out.Rollout.Stage)
	require.Nil(t, out.Rollout.EligibleAt)
	require.Contains(t, oqCall(f.h, pinGet, http.MethodGet, "alice", nodeVals(f.envA, "NODE-A"), "").Body.String(), `"eligible_at":null`)
}

func TestNodeOsqueryRolloutPausedHasNoEligibleAt(t *testing.T) {
	f := setupOsqueryHandlers(t)
	nodeRolloutFixture(t, f, 2)
	var r osqueryversions.Rollout
	require.NoError(t, f.db.Where("environment_id = ?", f.envA.ID).First(&r).Error)
	ok, err := f.mgr.PauseRollout(f.envA.ID, r.RequestID, "web-1", "version_not_reported", time.Now(), time.Now())
	require.NoError(t, err)
	require.True(t, ok)
	out := getNodeOsquery(t, f)
	require.NotNil(t, out.Rollout)
	require.Equal(t, "paused", out.Rollout.State)
	require.Equal(t, 3, out.Rollout.Stage)
	require.Nil(t, out.Rollout.EligibleAt)
}

func TestNodeOsqueryRolloutAbsent(t *testing.T) {
	f := setupOsqueryHandlers(t)
	require.Nil(t, getNodeOsquery(t, f).Rollout, "no rollout")

	nodeRolloutFixture(t, f, 2)
	require.NotNil(t, getNodeOsquery(t, f).Rollout)

	// a pin wins over the environment target
	_, err := f.mgr.SetPin("NODE-A", f.envA.ID, "5.13.0", nil, "alice")
	require.NoError(t, err)
	require.Nil(t, getNodeOsquery(t, f).Rollout, "pin")
	_, err = f.mgr.DeletePin("NODE-A")
	require.NoError(t, err)

	// a rollout of another request does not describe the target
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("request_id", "other").Error)
	require.Nil(t, getNodeOsquery(t, f).Rollout, "request mismatch")
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("request_id", f.targetRequestID(t)).Error)
	require.NotNil(t, getNodeOsquery(t, f).Rollout)

	// completed
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("stage_opened_at", time.Now().Add(-7*time.Hour)).Error)
	require.Nil(t, getNodeOsquery(t, f).Rollout, "completed")

	// windows hosts are in the rollout like any other
	require.NoError(t, f.db.Model(&osqueryversions.Rollout{}).Where("environment_id = ?", f.envA.ID).Update("stage_opened_at", time.Now()).Error)
	require.NotNil(t, getNodeOsquery(t, f).Rollout)
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", "windows").Error)
	require.NotNil(t, getNodeOsquery(t, f).Rollout, "windows")
	// hosts without a package are outside it
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", "freebsd").Error)
	require.Nil(t, getNodeOsquery(t, f).Rollout, "freebsd")
}

func (f oqFixture) targetRequestID(t *testing.T) string {
	t.Helper()
	tg, err := f.mgr.GetEnvTarget(f.envA.ID)
	require.NoError(t, err)
	return tg.RequestID
}

// nodeRollout and Resolve must agree on who waits and who may upgrade.
func TestNodeOsqueryRolloutAgreesWithResolve(t *testing.T) {
	f := setupOsqueryHandlers(t)
	f.put(t, "5.12.1") // digest of the installed version, so Resolve can let the host through
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("osquery_version", "5.12.1").Error)
	resolve := func() string {
		res, err := f.mgr.Resolve(osqueryversions.ResolveInput{EnvironmentID: f.envA.ID, NodeUUID: "NODE-A",
			Platform: "linux", Arch: "amd64", Format: "deb", InstalledVersion: "5.12.1"}, time.Now())
		require.NoError(t, err)
		return res.Reason
	}

	nodeRolloutFixture(t, f, 2)
	require.Equal(t, osqueryversions.ReasonRolloutPending, resolve())
	out := getNodeOsquery(t, f)
	require.NotNil(t, out.Rollout)
	require.NotNil(t, out.Rollout.EligibleAt)
	require.Greater(t, out.Rollout.Stage, 1) // current stage is 1

	nodeRolloutFixture(t, f, 0)
	require.Equal(t, "", resolve())
	out = getNodeOsquery(t, f)
	require.NotNil(t, out.Rollout)
	require.Nil(t, out.Rollout.EligibleAt)
}

// The thresholds computed at rollout start (UUIDsByEnv) and the hosts Progress
// counts must be the same set, Windows included and unsupported platforms out.
func TestThresholdsAndProgressUseSameHostSet(t *testing.T) {
	f := setupOsqueryHandlers(t)
	for _, n := range []nodes.OsqueryNode{
		{UUID: "NODE-WIN", EnvironmentID: f.envA.ID, Platform: "windows", OsqueryVersion: "5.12.1"},
		{UUID: "NODE-BSD", EnvironmentID: f.envA.ID, Platform: "freebsd", OsqueryVersion: "5.12.1"},
	} {
		require.NoError(t, f.db.Create(&n).Error)
	}
	f.put(t, "5.13.0")
	rr := oqCall(f.h, envPut, http.MethodPut, "alice", map[string]string{"env": f.envA.Name}, `{"version":"5.13.0"}`)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	uuids, err := f.h.Nodes.UUIDsByEnv(f.envA.ID)
	require.NoError(t, err)
	require.Contains(t, uuids, "NODE-WIN")
	require.NotContains(t, uuids, "NODE-BSD")
	r, err := f.mgr.GetRollout(f.envA.ID)
	require.NoError(t, err)
	r.StageOpenedAt = time.Now().Add(-7 * time.Hour) // final stage: every counted host is eligible
	p, err := f.mgr.Progress(*r, time.Now())
	require.NoError(t, err)
	require.Equal(t, len(uuids), p.Counts.Eligible)
}

func TestEnvOsqueryWindowsHosts(t *testing.T) {
	f := setupOsqueryHandlers(t)
	get := func() int {
		rr := oqCall(f.h, envGet, http.MethodGet, "alice", map[string]string{"env": f.envA.Name}, "")
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var out types.EnvOsqueryResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
		return out.WindowsHosts
	}
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", "ubuntu").Error)
	require.Equal(t, 0, get())
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", "NODE-A").Update("platform", "Windows").Error)
	require.Equal(t, 1, get())
}
