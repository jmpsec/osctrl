package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type osqueryFixture struct {
	h          *HandlersTLS
	db         *gorm.DB
	m          *osqueryversions.Manager
	env, other environments.TLSEnvironment
}

func newOsqueryFixture(t *testing.T) *osqueryFixture {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	envs := environments.CreateEnvironment(db)
	nodesRepo := nodes.CreateNodes(db)
	t.Cleanup(nodesRepo.Cache.Close)
	f := &osqueryFixture{
		db:    db,
		env:   environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "osq-env", Secret: "osctrld-secret"},
		other: environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "osq-other", Secret: "other-secret"},
	}
	require.NoError(t, db.Create(&f.env).Error)
	require.NoError(t, db.Create(&f.other).Error)
	for _, n := range []nodes.OsqueryNode{
		{NodeKey: "key-a", UUID: nfNodeA, EnvironmentID: f.env.ID, OsqueryVersion: "5.12.1"},
		{NodeKey: "key-other", UUID: nfNodeOther, EnvironmentID: f.other.ID},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	f.m, err = osqueryversions.NewManager(db)
	require.NoError(t, err)
	f.h = CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesRepo), WithOsqueryVersions(f.m),
		WithOsctrldLimits(NewOsctrldLimits(config.DefaultRateLimits())))
	return f
}

func (f *osqueryFixture) seed(t *testing.T) {
	t.Helper()
	require.NoError(t, f.m.PutEntries("5.12.1", []osqueryversions.DigestEntry{{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: strings.Repeat("a", 64)}}, "t"))
	require.NoError(t, f.m.PutEntries("5.13.0", []osqueryversions.DigestEntry{{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: strings.Repeat("b", 64)}}, "t"))
	_, err := f.m.SetEnvTarget(f.env.ID, "5.13.0", "t")
	require.NoError(t, err)
}

func (f *osqueryFixture) post(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/osctrld-osquery", bytes.NewBufferString(body))
	r.RemoteAddr = "198.51.100.7:40000"
	r.SetPathValue("env", f.env.UUID)
	w := httptest.NewRecorder()
	f.h.OsqueryHandler(w, r)
	return w
}

func osqBody(secret, uuid, platform, arch, format, installed string) string {
	return `{"secret":"` + secret + `","uuid":"` + uuid + `","platform":"` + platform + `","arch":"` + arch +
		`","format":"` + format + `","installed_version":"` + installed + `"}`
}

func TestOsqueryHandlerWireContract(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	tgt, err := f.m.GetEnvTarget(f.env.ID)
	require.NoError(t, err)
	w := f.post(osqBody(f.env.Secret, nfNodeA, "linux", "amd64", "deb", "5.12.1"))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"reason":"","source":"environment","request_id":"`+tgt.RequestID+`",`+
		`"target":{"version":"5.13.0","sha256":"`+strings.Repeat("b", 64)+`"},`+
		`"previous":{"version":"5.12.1","sha256":"`+strings.Repeat("a", 64)+`"},"reported_version":"5.12.1"}`, w.Body.String())
	// A lower-case uuid and an installed version at the target: ahead_of_target keeps source/request_id only.
	w = f.post(osqBody(f.env.Secret, strings.ToLower(nfNodeA), "linux", "amd64", "deb", "5.13.0"))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"reason":"ahead_of_target","source":"environment","request_id":"`+tgt.RequestID+`","reported_version":"5.12.1"}`, w.Body.String())
}

func TestOsqueryHandlerNoTargetOmitsSource(t *testing.T) {
	f := newOsqueryFixture(t)
	w := f.post(osqBody(f.env.Secret, nfNodeA, "linux", "amd64", "deb", "5.12.1"))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"reason":"no_target","reported_version":"5.12.1"}`, w.Body.String())
}

func TestOsqueryHandlerRejectsBadUUIDAndBody(t *testing.T) {
	f := newOsqueryFixture(t)
	s := f.env.Secret
	for name, body := range map[string]string{
		"bad uuid":      osqBody(s, "not-a-uuid", "linux", "amd64", "deb", ""),
		"no uuid":       `{"secret":"` + s + `"}`,
		"bad json":      `{"secret":`,
		"empty":         ``,
		"upper platf":   osqBody(s, nfNodeA, "Linux", "amd64", "deb", ""),
		"empty platf":   osqBody(s, nfNodeA, "", "amd64", "deb", ""),
		"long arch":     osqBody(s, nfNodeA, "linux", strings.Repeat("a", 17), "deb", ""),
		"path format":   osqBody(s, nfNodeA, "linux", "amd64", "../x", ""),
		"bad installed": osqBody(s, nfNodeA, "linux", "amd64", "deb", "5.12.1; rm"),
	} {
		w := f.post(body)
		require.Equal(t, http.StatusBadRequest, w.Code, name)
		require.Empty(t, w.Body.String(), name)
	}
	big := osqBody(s, nfNodeA, "linux", "amd64", "deb", "") + strings.Repeat(" ", maxBodyOsquery)
	require.Equal(t, http.StatusRequestEntityTooLarge, f.post(big).Code)
}

func TestOsqueryHandlerOtherEnvironmentNodeIs400(t *testing.T) {
	f := newOsqueryFixture(t)
	a := f.post(osqBody(f.env.Secret, nfNodeOther, "linux", "amd64", "deb", ""))
	b := f.post(osqBody(f.env.Secret, "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", "linux", "amd64", "deb", ""))
	require.Equal(t, http.StatusBadRequest, a.Code)
	require.Equal(t, a.Code, b.Code)
	require.Equal(t, a.Body.String(), b.Body.String())
	require.Empty(t, a.Body.String())
}

func TestOsqueryHandlerWrongSecretIs403(t *testing.T) {
	f := newOsqueryFixture(t)
	require.Equal(t, http.StatusForbidden, f.post(osqBody("wrong", nfNodeA, "linux", "amd64", "deb", "")).Code)
	require.Equal(t, http.StatusForbidden, f.post(osqBody(f.other.Secret, nfNodeA, "linux", "amd64", "deb", "")).Code)
}

func TestOsqueryHandlerNeverAnswers404(t *testing.T) {
	f := newOsqueryFixture(t)
	s := f.env.Secret
	for name, body := range map[string]string{
		"bad json":    `{`,
		"bad uuid":    osqBody(s, "x", "linux", "amd64", "deb", ""),
		"other env":   osqBody(s, nfNodeOther, "linux", "amd64", "deb", ""),
		"unknown":     osqBody(s, "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", "linux", "amd64", "deb", ""),
		"bad secret":  osqBody("x", nfNodeA, "linux", "amd64", "deb", ""),
		"bad platf":   osqBody(s, nfNodeA, "!", "amd64", "deb", ""),
		"unsupported": osqBody(s, nfNodeA, "freebsd", "amd64", "deb", ""),
	} {
		code := f.post(body).Code
		require.NotEqual(t, http.StatusNotFound, code, name)
		require.NotEqual(t, http.StatusMethodNotAllowed, code, name)
	}
	require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("osqfail", func(tx *gorm.DB) { _ = tx.AddError(errors.New("injected")) }))
	code := f.post(osqBody(s, nfNodeA, "linux", "amd64", "deb", "")).Code
	require.NotEqual(t, http.StatusNotFound, code)
	require.NotEqual(t, http.StatusMethodNotAllowed, code)
}

func TestOsqueryHandlerUnsupportedPlatformIs200WithReason(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	w := f.post(osqBody(f.env.Secret, nfNodeA, "windows", "386", "msi", "5.12.1"))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{"reason":"unsupported_platform","reported_version":"5.12.1"}`, w.Body.String())
}

// The node check comes first: an unknown node gets 400 even for an unsupported platform.
func TestOsqueryHandlerUnsupportedPlatformUnknownNodeIs400(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	w := f.post(osqBody(f.env.Secret, "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", "windows", "amd64", "msi", "5.12.1"))
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, w.Body.String())
}

func TestOsqueryHandlerRejectsOversizedInstalledVersion(t *testing.T) {
	f := newOsqueryFixture(t)
	w := f.post(osqBody(f.env.Secret, nfNodeA, "linux", "amd64", "deb", strings.Repeat("1", 3000)))
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, w.Body.String())
}

func TestOsqueryHandlerDBErrorIs500NotFound400(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register("osqfail", func(tx *gorm.DB) {
		if tx.Statement.Table == "osquery_nodes" {
			_ = tx.AddError(errors.New("injected db error"))
		}
	}))
	w := f.post(osqBody(f.env.Secret, nfNodeA, "linux", "amd64", "deb", "5.12.1"))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Empty(t, w.Body.String())
}

// A pin is keyed by the node row's UUID (upper case), so a request with a
// lower-case uuid still resolves it.
func TestOsqueryHandlerAppliesPinKeyedByNodeRowUUID(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	_, err := f.m.SetPin(nfNodeA, f.env.ID, "5.12.1", nil, "t")
	require.NoError(t, err)
	w := f.post(osqBody(f.env.Secret, strings.ToLower(nfNodeA), "linux", "amd64", "deb", "5.12.1"))
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"source":"pin"`)
}

func TestOsqueryHandlerWindowsTargetWithoutPrevious(t *testing.T) {
	f := newOsqueryFixture(t)
	f.seed(t)
	require.NoError(t, f.m.PutEntries("5.13.0", []osqueryversions.DigestEntry{{Platform: "windows", Arch: "amd64", Format: "msi", SHA256: strings.Repeat("c", 64)}}, "t"))
	w := f.post(osqBody(f.env.Secret, nfNodeA, "windows", "amd64", "msi", "5.12.1"))
	require.Equal(t, http.StatusOK, w.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Equal(t, "", got["reason"])
	require.Equal(t, map[string]any{"version": "5.13.0", "sha256": strings.Repeat("c", 64)}, got["target"])
	require.NotContains(t, got, "previous")
}
