package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newUnknownEnvHandlers(t *testing.T) (*HandlersTLS, *gorm.DB, environments.TLSEnvironment) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	envs := environments.CreateEnvironment(db)
	future := time.Now().Add(time.Hour)
	env := environments.TLSEnvironment{
		UUID: "11111111-1111-4111-8111-111111111111", Name: "known", Secret: "right-secret",
		EnrollSecretPath: "right-enroll-path", RemoveSecretPath: "right-remove-path",
		EnrollExpire: future, RemoveExpire: future, AcceptEnrolls: true,
	}
	other := environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "other", Secret: "other-secret"}
	require.NoError(t, db.Create(&env).Error)
	require.NoError(t, db.Create(&other).Error)
	nodesmgr := nodes.CreateNodes(db)
	// A real node key, but for another environment.
	require.NoError(t, nodesmgr.Create(&nodes.OsqueryNode{UUID: "NODE-OTHER", NodeKey: "other-key", EnvironmentID: other.ID, Environment: "other"}))
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	h := CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesmgr), WithAuditLog(audit),
		WithCarves(carves.CreateFileCarves(db, config.CarverDB, nil)))
	return h, db, env
}

// An environment that does not exist must be answered exactly like a known
// environment given a bad credential, so a scanner cannot enumerate UUIDs.
func TestUnknownEnvironmentMatchesBadCredential(t *testing.T) {
	h, _, env := newUnknownEnvHandlers(t)
	type tc struct {
		name    string
		handler func(*HandlersTLS) http.HandlerFunc
		path    map[string]string
		body    string
	}
	nodeKeyCases := func(name string, fn func(*HandlersTLS) http.HandlerFunc) []tc {
		return []tc{
			{name + "/unknown key", fn, nil, `{"node_key":"no-such-key"}`},
			{name + "/other env key", fn, nil, `{"node_key":"other-key"}`},
			{name + "/malformed", fn, nil, `{`},
		}
	}
	var cases []tc
	cases = append(cases,
		tc{"enroll/wrong secret", func(h *HandlersTLS) http.HandlerFunc { return h.EnrollHandler }, nil, `{"enroll_secret":"wrong","host_identifier":"h"}`},
		tc{"enroll/empty secret", func(h *HandlersTLS) http.HandlerFunc { return h.EnrollHandler }, nil, `{"enroll_secret":"","host_identifier":"h"}`},
		tc{"enroll/malformed", func(h *HandlersTLS) http.HandlerFunc { return h.EnrollHandler }, nil, `{`},
	)
	cases = append(cases, nodeKeyCases("config", func(h *HandlersTLS) http.HandlerFunc { return h.ConfigHandler })...)
	cases = append(cases, nodeKeyCases("log", func(h *HandlersTLS) http.HandlerFunc { return h.LogHandler })...)
	cases = append(cases, nodeKeyCases("query read", func(h *HandlersTLS) http.HandlerFunc { return h.QueryReadHandler })...)
	cases = append(cases, nodeKeyCases("query write", func(h *HandlersTLS) http.HandlerFunc { return h.QueryWriteHandler })...)
	cases = append(cases, nodeKeyCases("carve init", func(h *HandlersTLS) http.HandlerFunc { return h.CarveInitHandler })...)
	cases = append(cases,
		tc{"carve block/unknown session", func(h *HandlersTLS) http.HandlerFunc { return h.CarveBlockHandler }, nil, `{"block_id":0,"session_id":"s","request_id":"r","data":""}`},
	)
	for _, q := range []struct {
		name string
		fn   func(*HandlersTLS) http.HandlerFunc
	}{
		{"quick enroll", func(h *HandlersTLS) http.HandlerFunc { return h.QuickEnrollHandler }},
		{"quick remove", func(h *HandlersTLS) http.HandlerFunc { return h.QuickRemoveHandler }},
	} {
		for _, script := range []string{environments.EnrollShell, environments.RemoveShell, "bogus.sh"} {
			cases = append(cases, tc{q.name + "/" + script, q.fn, map[string]string{"script": script, "secretpath": "wrong"}, ``})
		}
		cases = append(cases, tc{q.name + "/empty path", q.fn, map[string]string{"script": environments.EnrollShell, "secretpath": " "}, ``})
	}
	for _, o := range []struct {
		name string
		fn   func(*HandlersTLS) http.HandlerFunc
		path map[string]string
	}{
		{"flags", func(h *HandlersTLS) http.HandlerFunc { return h.FlagsHandler }, nil},
		{"cert", func(h *HandlersTLS) http.HandlerFunc { return h.CertHandler }, nil},
		{"verify", func(h *HandlersTLS) http.HandlerFunc { return h.VerifyHandler }, nil},
		{"script", func(h *HandlersTLS) http.HandlerFunc { return h.ScriptHandler }, map[string]string{"action": "enroll", "platform": "linux"}},
		{"script bad platform", func(h *HandlersTLS) http.HandlerFunc { return h.ScriptHandler }, map[string]string{"action": "enroll", "platform": "nope"}},
		{"extensions", func(h *HandlersTLS) http.HandlerFunc { return h.ExtensionsHandler }, nil},
		{"extension download", func(h *HandlersTLS) http.HandlerFunc { return h.ExtensionDownloadHandler }, nil},
		{"status", func(h *HandlersTLS) http.HandlerFunc { return h.StatusHandler }, nil},
		{"osquery", func(h *HandlersTLS) http.HandlerFunc { return h.OsqueryHandler }, nil},
	} {
		cases = append(cases,
			tc{o.name + "/wrong secret", o.fn, o.path, `{"secret":"wrong"}`},
			tc{o.name + "/empty secret", o.fn, o.path, `{"secret":""}`},
			tc{o.name + "/malformed", o.fn, o.path, `{`},
		)
	}
	cases = append(cases,
		tc{"enroll package/wrong path", func(h *HandlersTLS) http.HandlerFunc { return h.EnrollPackageHandler }, map[string]string{"package": "deb", "secretpath": "wrong"}, ``},
		tc{"enroll package/bad package", func(h *HandlersTLS) http.HandlerFunc { return h.EnrollPackageHandler }, map[string]string{"package": "nope", "secretpath": "wrong"}, ``},
	)

	send := func(c tc, envUUID string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		r.SetPathValue("env", envUUID)
		for k, v := range c.path {
			r.SetPathValue(k, v)
		}
		w := httptest.NewRecorder()
		c.handler(h)(w, r)
		return w
	}
	counter := unknownEnvironment.WithLabelValues("CertHandler")
	before := metricValue(t, counter)
	statusCounter := unknownEnvironment.WithLabelValues("StatusHandler")
	statusBefore := metricValue(t, statusCounter)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			known := send(c, env.UUID)
			unknown := send(c, uuid.NewString())
			require.Equal(t, known.Code, unknown.Code, "status")
			require.Equal(t, known.Header().Get("Content-Type"), unknown.Header().Get("Content-Type"), "content type")
			require.Equal(t, known.Body.String(), unknown.Body.String(), "body")
		})
	}
	// Three cert cases each sent one unknown-environment request.
	require.Equal(t, before+3, metricValue(t, counter))
	require.Equal(t, statusBefore+3, metricValue(t, statusCounter))
}

// With osctrld limits on, an unknown environment spends the failed-secret
// budget and turns to 429 exactly like a wrong secret for a known one.
func TestOsctrldUnknownEnvironmentChargesBudget(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldAuth.Burst = 2
	f := newOsctrldFixture(t, cfg)
	unknown := environments.TLSEnvironment{UUID: uuid.NewString()}
	for _, env := range []environments.TLSEnvironment{f.env, unknown} {
		require.Equal(t, http.StatusForbidden, f.cert("198.51.100.9", env, "wrong"))
		require.Equal(t, http.StatusForbidden, f.cert("198.51.100.9", env, "wrong"))
		require.Equal(t, http.StatusTooManyRequests, f.cert("198.51.100.9", env, "wrong"))
	}
}

// A known environment with enrolls disabled answers a wrong secret like an
// unknown environment; only the right secret learns enrolls are off (503).
// An unknown environment enrolls nothing and writes no audit row.
func TestEnrollDisabledAndUnknownEnvironment(t *testing.T) {
	h, db, _ := newUnknownEnvHandlers(t)
	disabled := environments.TLSEnvironment{UUID: "33333333-3333-4333-8333-333333333333", Name: "disabled", Secret: "disabled-secret"}
	require.NoError(t, db.Create(&disabled).Error)
	require.NoError(t, db.Model(&disabled).Update("accept_enrolls", false).Error)
	enroll := func(envUUID, secret string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"enroll_secret":"`+secret+`","host_identifier":"h"}`))
		r.SetPathValue("env", envUUID)
		w := httptest.NewRecorder()
		h.EnrollHandler(w, r)
		return w
	}
	var nodesBefore, auditsBefore int64
	require.NoError(t, db.Model(&nodes.OsqueryNode{}).Count(&nodesBefore).Error)
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Count(&auditsBefore).Error)
	unknown := enroll(uuid.NewString(), "disabled-secret")
	var nodesAfter, auditsAfter int64
	require.NoError(t, db.Model(&nodes.OsqueryNode{}).Count(&nodesAfter).Error)
	require.NoError(t, db.Model(&auditlog.AuditLog{}).Count(&auditsAfter).Error)
	require.Equal(t, nodesBefore, nodesAfter, "unknown env enroll created a node")
	require.Equal(t, auditsBefore, auditsAfter, "unknown env enroll wrote an audit row")

	wrong := enroll(disabled.UUID, "wrong")
	require.Equal(t, unknown.Code, wrong.Code, "status")
	require.Equal(t, unknown.Header().Get("Content-Type"), wrong.Header().Get("Content-Type"), "content type")
	require.Equal(t, unknown.Body.String(), wrong.Body.String(), "body")

	require.Equal(t, http.StatusServiceUnavailable, enroll(disabled.UUID, "disabled-secret").Code)
	require.NoError(t, db.Model(&nodes.OsqueryNode{}).Count(&nodesAfter).Error)
	require.Equal(t, nodesBefore, nodesAfter, "disabled env enrolled a node")
}

// Only "not found" is an unknown environment: a failing database still
// answers 500.
func TestEnvironmentLookupErrorStill500(t *testing.T) {
	h, db, env := newUnknownEnvHandlers(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	for name, fn := range map[string]http.HandlerFunc{"config": h.ConfigHandler, "cert": h.CertHandler, "enroll": h.EnrollHandler} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"node_key":"k","secret":"s"}`))
		r.SetPathValue("env", env.UUID)
		w := httptest.NewRecorder()
		fn(w, r)
		require.Equal(t, http.StatusInternalServerError, w.Code, name)
	}
}
