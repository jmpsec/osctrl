package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/ratelimit"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	osctrldCertRoute     = "POST /{env}/" + environments.DefaultCertPath
	osctrldDownloadRoute = "POST /{env}/" + environments.DefaultExtensionPath
)

type osctrldFixture struct {
	h          *HandlersTLS
	db         *gorm.DB
	mux        *http.ServeMux
	env, other environments.TLSEnvironment
}

// newOsctrldFixture serves the cert route and the extension download route
// through OsctrldMiddleware, with limits built from cfg.
func newOsctrldFixture(t *testing.T, cfg config.YAMLConfigurationRateLimits) *osctrldFixture {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1)
	envs := environments.CreateEnvironment(db)
	f := &osctrldFixture{
		db:    db,
		env:   environments.TLSEnvironment{UUID: "abcdef01-1111-4111-8111-111111111111", Name: "limits-env", Secret: "osctrld-secret", Certificate: "CERT"},
		other: environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "limits-other", Secret: "other-secret", Certificate: "CERT"},
	}
	require.NoError(t, db.Create(&f.env).Error)
	require.NoError(t, db.Create(&f.other).Error)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	f.h = CreateHandlersTLS(WithEnvs(envs), WithAuditLog(audit), WithOsctrldLimits(NewOsctrldLimits(cfg)))
	f.mux = http.NewServeMux()
	f.mux.Handle(osctrldCertRoute, f.h.OsctrldMiddleware(false, http.HandlerFunc(f.h.CertHandler)))
	f.mux.Handle(osctrldDownloadRoute, f.h.OsctrldMiddleware(true, http.HandlerFunc(f.h.ExtensionDownloadHandler)))
	return f
}

func (f *osctrldFixture) post(ip, path string, env environments.TLSEnvironment, secret string) *httptest.ResponseRecorder {
	return f.postXFF(ip, "", path, env, secret)
}

func (f *osctrldFixture) postXFF(ip, xff, path string, env environments.TLSEnvironment, secret string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"secret": secret})
	r := httptest.NewRequest(http.MethodPost, "/"+env.UUID+"/"+path, bytes.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	if xff != "" {
		r.Header.Set(utils.XForwardedFor, xff)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func (f *osctrldFixture) cert(ip string, env environments.TLSEnvironment, secret string) int {
	return f.post(ip, environments.DefaultCertPath, env, secret).Code
}

func (f *osctrldFixture) audits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, f.db.Model(&auditlog.AuditLog{}).Where("line LIKE ?", "failed osctrld secret%").Count(&n).Error)
	return n
}

func TestOsctrldAuthLimitBlocksOnlyFailingAddressAndEnv(t *testing.T) {
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	const attacker, nat, neighbour = "198.51.100.7", "198.51.100.8", "198.51.100.9"
	// A shared NAT with many healthy hosts: correct secrets never charge the
	// failure budget.
	for i := 0; i < 100; i++ {
		require.Equal(t, http.StatusOK, f.cert(nat, f.env, f.env.Secret), "correct secret #%d", i+1)
	}
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusForbidden, f.cert(attacker, f.env, "wrong"), "failure #%d", i+1)
	}
	// Budget spent: blocked even with the right secret, before the check.
	w := f.post(attacker, environments.DefaultCertPath, f.env, f.env.Secret)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, "360", w.Header().Get("Retry-After"))
	// The block is per address and environment.
	require.Equal(t, http.StatusOK, f.cert(attacker, f.other, f.other.Secret))
	require.Equal(t, http.StatusOK, f.cert(neighbour, f.env, f.env.Secret))
	require.Equal(t, http.StatusOK, f.cert(nat, f.env, f.env.Secret))
	// The upper-case spelling of the environment shares the same budget.
	upper := f.env
	upper.UUID = strings.ToUpper(upper.UUID)
	require.Equal(t, http.StatusTooManyRequests, f.cert(attacker, upper, f.env.Secret))
}

func TestOsctrldAuthBlockRefills(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldAuth = config.YAMLConfigurationRateLimit{Burst: 1, Period: 50 * time.Millisecond, EvictAfter: time.Minute, RetryAfter: 1}
	f := newOsctrldFixture(t, cfg)
	require.Equal(t, http.StatusForbidden, f.cert("198.51.100.7", f.env, "wrong"))
	require.Equal(t, http.StatusTooManyRequests, f.cert("198.51.100.7", f.env, f.env.Secret))
	time.Sleep(60 * time.Millisecond)
	require.Equal(t, http.StatusOK, f.cert("198.51.100.7", f.env, f.env.Secret))
}

func TestOsctrldFailedSecretAuditThrottled(t *testing.T) {
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	const ip = "198.51.100.7"
	for i := 0; i < 10; i++ {
		f.cert(ip, f.env, "wrong")
	}
	require.EqualValues(t, 10, f.audits(t), "every failed secret is audited")
	for i := 0; i < 20; i++ {
		require.Equal(t, http.StatusTooManyRequests, f.cert(ip, f.env, "wrong"))
	}
	require.EqualValues(t, 11, f.audits(t), "only the first rejection while blocked is audited")
	var row auditlog.AuditLog
	require.NoError(t, f.db.Order("id desc").First(&row).Error)
	require.Equal(t, ip, row.SourceIP)
	require.Equal(t, f.env.ID, row.EnvironmentID)
	require.Contains(t, row.Line, f.env.Name)
}

func TestOsctrldTrafficLimit(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.Osctrld.Burst = 3
	cfg.Osctrld.RetryAfter = 11
	f := newOsctrldFixture(t, cfg)
	limited := osctrldRateLimited.WithLabelValues(osctrldCertRoute, "osctrld")
	before := metricValue(t, limited)
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.cert("198.51.100.7", f.env, f.env.Secret))
	}
	w := f.post("198.51.100.7", environments.DefaultCertPath, f.env, f.env.Secret)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, "11", w.Header().Get("Retry-After"))
	require.Equal(t, before+1, metricValue(t, limited))
	require.Equal(t, http.StatusOK, f.cert("198.51.100.8", f.env, f.env.Secret))
}

func TestOsctrldDownloadLimit(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldDownload.Burst = 2
	f := newOsctrldFixture(t, cfg)
	limited := osctrldRateLimited.WithLabelValues(osctrldDownloadRoute, "osctrldDownload")
	before := metricValue(t, limited)
	for i := 0; i < 2; i++ {
		// No extension with this SHA: past the limiter the handler answers 400.
		require.NotEqual(t, http.StatusTooManyRequests, f.post("198.51.100.7", environments.DefaultExtensionPath, f.env, f.env.Secret).Code)
	}
	w := f.post("198.51.100.7", environments.DefaultExtensionPath, f.env, f.env.Secret)
	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.Equal(t, "60", w.Header().Get("Retry-After"))
	require.Equal(t, before+1, metricValue(t, limited))
	// Downloads have their own budget: other osctrld routes still pass.
	require.Equal(t, http.StatusOK, f.cert("198.51.100.7", f.env, f.env.Secret))
}

func TestOsctrldMetrics(t *testing.T) {
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	failures := osctrldAuthFailures.WithLabelValues(f.env.Name)
	authLimited := osctrldRateLimited.WithLabelValues(osctrldCertRoute, "osctrldAuth")
	failBefore, limitedBefore := metricValue(t, failures), metricValue(t, authLimited)
	requestDuration.Reset()
	f.cert("198.51.100.7", f.env, f.env.Secret)
	for i := 0; i < 11; i++ {
		f.cert("198.51.100.7", f.env, "wrong")
	}
	require.Equal(t, failBefore+10, metricValue(t, failures))
	require.Equal(t, limitedBefore+1, metricValue(t, authLimited))
	// Latency is labelled by route pattern, never by the raw URL path.
	for _, code := range []string{"200", "403", "429"} {
		require.True(t, requestDuration.DeleteLabelValues(http.MethodPost, osctrldCertRoute, code), code)
	}
	require.Zero(t, metricSeries(t, requestDuration))
}

// Every osctrld handler charges the failure budget, counts and audits a
// wrong secret, and answers 403.
func TestOsctrldHandlersChargeFailedSecret(t *testing.T) {
	for name, call := range map[string]func(h *HandlersTLS) http.HandlerFunc{
		"flags":      func(h *HandlersTLS) http.HandlerFunc { return h.FlagsHandler },
		"cert":       func(h *HandlersTLS) http.HandlerFunc { return h.CertHandler },
		"verify":     func(h *HandlersTLS) http.HandlerFunc { return h.VerifyHandler },
		"script":     func(h *HandlersTLS) http.HandlerFunc { return h.ScriptHandler },
		"extensions": func(h *HandlersTLS) http.HandlerFunc { return h.ExtensionsHandler },
		"extension":  func(h *HandlersTLS) http.HandlerFunc { return h.ExtensionDownloadHandler },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultRateLimits()
			cfg.OsctrldAuth.Burst = 1
			f := newOsctrldFixture(t, cfg)
			failures := osctrldAuthFailures.WithLabelValues(f.env.Name)
			before := metricValue(t, failures)
			r := httptest.NewRequest(http.MethodPost, "/osctrld", strings.NewReader(`{"secret":"wrong"}`))
			r.RemoteAddr = "198.51.100.7:40000"
			r.SetPathValue("env", f.env.UUID)
			r.SetPathValue("action", "enroll")
			r.SetPathValue("platform", "linux")
			w := httptest.NewRecorder()
			call(f.h)(w, r)
			require.Equal(t, http.StatusForbidden, w.Code)
			require.True(t, f.h.OsctrldLimits.Auth.Exhausted(osctrldAuthKey("198.51.100.7", f.env.UUID)))
			require.Equal(t, before+1, metricValue(t, failures))
			require.EqualValues(t, 1, f.audits(t))
		})
	}
}

// Without limits (OsctrldLimits nil) the middleware only records metrics.
func TestOsctrldMiddlewareWithoutLimits(t *testing.T) {
	h := &HandlersTLS{}
	called := 0
	mw := h.OsctrldMiddleware(true, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called++ }))
	for i := 0; i < 50; i++ {
		mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/x", nil))
	}
	require.Equal(t, 50, called)
}

// metricValue reads a counter through a throwaway registry.
func metricValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	return mfs[0].GetMetric()[0].GetCounter().GetValue()
}

// metricSeries counts the label sets a collector currently exports.
func metricSeries(t *testing.T, c prometheus.Collector) int {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	n := 0
	for _, mf := range mfs {
		n += len(mf.GetMetric())
	}
	return n
}

// Behind a trusted proxy the limits key on the forwarded client address, so
// one client's failures do not block the rest of the proxied fleet; the
// client cannot change its key by prepending a forged hop.
func TestOsctrldLimitsKeyOnTrustedProxyClient(t *testing.T) {
	utils.SetTrustedProxies([]string{"10.0.0.0/8"})
	t.Cleanup(func() { utils.SetTrustedProxies(nil) })
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	const proxy = "10.0.0.1"
	cert := func(xff, secret string) int {
		return f.postXFF(proxy, xff, environments.DefaultCertPath, f.env, secret).Code
	}
	for i := 0; i < 10; i++ {
		// The appending proxy adds the real client last; the forged
		// left-most entry changes on every request.
		require.Equal(t, http.StatusForbidden, cert("203.0.113."+strconv.Itoa(i)+", 198.51.100.7", "wrong"))
	}
	require.Equal(t, http.StatusTooManyRequests, cert("192.0.2.99, 198.51.100.7", f.env.Secret))
	require.Equal(t, http.StatusOK, cert("198.51.100.8", f.env.Secret), "another client behind the same proxy")
	var row auditlog.AuditLog
	require.NoError(t, f.db.Order("id").First(&row).Error)
	require.Equal(t, "198.51.100.7", row.SourceIP)
}

// Without trusted proxies the TCP peer is the key; forwarding headers are
// ignored.
func TestOsctrldLimitsIgnoreForwardingWithoutTrustedProxies(t *testing.T) {
	utils.SetTrustedProxies(nil)
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	for i := 0; i < 10; i++ {
		f.postXFF("198.51.100.7", "203.0.113."+strconv.Itoa(i), environments.DefaultCertPath, f.env, "wrong")
	}
	require.Equal(t, http.StatusTooManyRequests, f.postXFF("198.51.100.7", "203.0.113.200", environments.DefaultCertPath, f.env, f.env.Secret).Code)
}

// Requests that all passed the middleware before any body arrived are still
// charged atomically at the comparison: at most burst wrong secrets are
// compared and answered 403, the rest get 429.
func TestOsctrldConcurrentFailuresBounded(t *testing.T) {
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/osctrld", strings.NewReader(`{"secret":"wrong"}`))
			r.RemoteAddr = "198.51.100.7:40000"
			r.SetPathValue("env", f.env.UUID)
			w := httptest.NewRecorder()
			f.h.CertHandler(w, r) // as if every request had already passed OsctrldMiddleware
			mu.Lock()
			codes[w.Code]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Equal(t, map[int]int{http.StatusForbidden: 10, http.StatusTooManyRequests: 30}, codes)
	require.EqualValues(t, 11, f.audits(t), "10 failures and one blocked rejection")
}

// Past maxBuckets, addresses without their own bucket share the overflow
// budget, so a spray is blocked collectively.
func TestOsctrldOverflowBlocksSpray(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldAuth.MaxBuckets = 1
	cfg.OsctrldAuth.Burst = 2
	f := newOsctrldFixture(t, cfg)
	require.Equal(t, http.StatusForbidden, f.cert("198.51.100.1", f.env, "wrong")) // own bucket; map full
	for i := 2; i <= 3; i++ {
		require.Equal(t, http.StatusForbidden, f.cert("198.51.100."+strconv.Itoa(i), f.env, "wrong"))
	}
	require.Equal(t, http.StatusTooManyRequests, f.cert("198.51.100.4", f.env, "wrong"))
}

// Failed-secret audit writes are capped per environment; drops are counted.
func TestOsctrldAuditCapPerEnvironment(t *testing.T) {
	f := newOsctrldFixture(t, config.DefaultRateLimits())
	dropped := osctrldAuthAuditDropped.WithLabelValues(f.env.Name)
	before := metricValue(t, dropped)
	for a := 0; a < 7; a++ {
		for i := 0; i < 10; i++ {
			require.Equal(t, http.StatusForbidden, f.cert("198.51.100."+strconv.Itoa(a), f.env, "wrong"))
		}
	}
	require.EqualValues(t, osctrldAuditPerHour, f.audits(t))
	require.Equal(t, before+70-osctrldAuditPerHour, metricValue(t, dropped))
}

// A blocked rejection under an upper-case spelling of the environment is
// audited against the right environment.
func TestOsctrldBlockedAuditResolvesUpperCaseEnv(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldAuth.Burst = 1
	f := newOsctrldFixture(t, cfg)
	f.cert("198.51.100.7", f.env, "wrong")
	upper := f.env
	upper.UUID = strings.ToUpper(upper.UUID)
	require.Equal(t, http.StatusTooManyRequests, f.cert("198.51.100.7", upper, f.env.Secret))
	var row auditlog.AuditLog
	require.NoError(t, f.db.Order("id desc").First(&row).Error)
	require.Contains(t, row.Line, "blocked")
	require.Equal(t, f.env.ID, row.EnvironmentID)
	require.Contains(t, row.Line, f.env.Name)
}

// Blocked rejections for environments that do not resolve all share one
// "<unknown>" audit cap, audit environment and metric label, however many
// made-up UUIDs are used. Known environments keep their own.
func TestOsctrldUnknownEnvsShareAuditCap(t *testing.T) {
	cfg := config.DefaultRateLimits()
	cfg.OsctrldAuth.Burst = 1
	cfg.OsctrldAuth.MaxBuckets = 1
	f := newOsctrldFixture(t, cfg)
	f.h.OsctrldLimits.authAudit = ratelimit.New(1, time.Hour, 2*time.Hour)
	// Fill the map, then spend the shared overflow budget.
	require.Equal(t, http.StatusForbidden, f.cert("198.51.100.1", f.env, "wrong"))
	require.Equal(t, http.StatusForbidden, f.cert("198.51.100.2", f.env, "wrong"))
	dropped := osctrldAuthAuditDropped.WithLabelValues(osctrldUnknownEnv)
	before := metricValue(t, dropped)
	for i := 0; i < 70; i++ {
		unknown := environments.TLSEnvironment{UUID: fmt.Sprintf("%08d-1111-4111-8111-111111111111", i)}
		require.Equal(t, http.StatusTooManyRequests, f.cert("203.0.113."+strconv.Itoa(i), unknown, "wrong"))
	}
	var rows []auditlog.AuditLog
	require.NoError(t, f.db.Where("environment_id = ?", 0).Find(&rows).Error)
	require.Len(t, rows, osctrldAuditPerHour)
	for _, row := range rows {
		require.Contains(t, row.Line, "env "+osctrldUnknownEnv+":")
	}
	require.Equal(t, before+70-osctrldAuditPerHour, metricValue(t, dropped))
	// The known environment's audits were not touched by the unknown cap.
	var known int64
	require.NoError(t, f.db.Model(&auditlog.AuditLog{}).Where("environment_id = ?", f.env.ID).Count(&known).Error)
	require.EqualValues(t, 2, known)
	require.Equal(t, f.env.Name, f.h.osctrldAuditEnv(httptest.NewRequest(http.MethodPost, "/", nil), f.env.UUID).Name)
}
