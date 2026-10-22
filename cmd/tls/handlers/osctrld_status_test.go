package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type statusFixture struct {
	h          *HandlersTLS
	db         *gorm.DB
	m          *nodeconfig.FlagsManager
	env, other environments.TLSEnvironment
}

func newStatusFixture(t *testing.T) *statusFixture {
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
	f := &statusFixture{
		db:    db,
		env:   environments.TLSEnvironment{UUID: "11111111-1111-4111-8111-111111111111", Name: "status-env", Secret: "osctrld-secret"},
		other: environments.TLSEnvironment{UUID: "22222222-2222-4222-8222-222222222222", Name: "status-other", Secret: "other-secret"},
	}
	require.NoError(t, db.Create(&f.env).Error)
	require.NoError(t, db.Create(&f.other).Error)
	for _, n := range []nodes.OsqueryNode{
		{NodeKey: "key-a", UUID: nfNodeA, EnvironmentID: f.env.ID},
		{NodeKey: "key-other", UUID: nfNodeOther, EnvironmentID: f.other.ID},
	} {
		require.NoError(t, db.Create(&n).Error)
	}
	f.m, err = nodeconfig.NewFlagsManager(db, nil)
	require.NoError(t, err)
	audit, err := auditlog.CreateAuditLogManager(db, config.ServiceTLS, true)
	require.NoError(t, err)
	f.h = CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesRepo), WithFlagsOverrides(f.m), WithAuditLog(audit),
		WithOsctrldLimits(NewOsctrldLimits(config.DefaultRateLimits())))
	return f
}

func (f *statusFixture) post(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/osctrld-status", bytes.NewBufferString(body))
	r.RemoteAddr = "198.51.100.7:40000"
	r.SetPathValue("env", f.env.UUID)
	w := httptest.NewRecorder()
	f.h.StatusHandler(w, r)
	return w
}

func (f *statusFixture) rows(t *testing.T) []nodeconfig.OsctrldStatus {
	t.Helper()
	var rows []nodeconfig.OsctrldStatus
	require.NoError(t, f.db.Find(&rows).Error)
	return rows
}

func (f *statusFixture) rollbackAudits(t *testing.T) []auditlog.AuditLog {
	t.Helper()
	var rows []auditlog.AuditLog
	require.NoError(t, f.db.Where("line LIKE ?", "osctrld rollback%").Find(&rows).Error)
	return rows
}

var statusEvent = "1760000000000000000:" + strings.Repeat("a", 64)

func statusBody(secret, uuid, flagsStage, flagsEvent string) string {
	return `{"secret":"` + secret + `","uuid":"` + uuid + `","osquery_running":false,"down_since":"2026-10-22T10:00:00Z",` +
		`"flags":{"stage":"` + flagsStage + `","event_id":"` + flagsEvent + `"},"extensions":{"stage":"none","event_id":""}}`
}

func TestStatusHandlerStoresReport(t *testing.T) {
	f := newStatusFixture(t)
	w := f.post(statusBody(f.env.Secret, strings.ToLower(nfNodeA), "exhausted", statusEvent))
	require.Equal(t, http.StatusOK, w.Code)
	require.JSONEq(t, `{}`, w.Body.String())
	rows := f.rows(t)
	require.Len(t, rows, 1)
	require.Equal(t, nfNodeA, rows[0].NodeUUID, "keyed by the stored node UUID")
	require.EqualValues(t, f.env.ID, rows[0].EnvironmentID)
	require.NotNil(t, rows[0].OsqueryRunning)
	require.False(t, *rows[0].OsqueryRunning)
	require.Equal(t, "exhausted", rows[0].FlagsStage)
	require.Equal(t, statusEvent, rows[0].FlagsEventID)
}

func TestStatusHandlerRejectsOtherEnvironmentNode(t *testing.T) {
	f := newStatusFixture(t)
	require.Equal(t, http.StatusBadRequest, f.post(statusBody(f.env.Secret, nfNodeOther, "exhausted", statusEvent)).Code)
	require.Equal(t, http.StatusBadRequest, f.post(statusBody(f.env.Secret, "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", "none", "")).Code)
	require.Empty(t, f.rows(t))
	require.Empty(t, f.rollbackAudits(t))
}

func TestStatusHandlerRejectsBadUUIDAndBody(t *testing.T) {
	f := newStatusFixture(t)
	for name, body := range map[string]string{
		"bad uuid":  statusBody(f.env.Secret, "not-a-uuid", "none", ""),
		"no uuid":   `{"secret":"` + f.env.Secret + `"}`,
		"bad json":  `{"secret":`,
		"not json":  `hello`,
		"empty":     ``,
		"wrong typ": `{"secret":"` + f.env.Secret + `","osquery_running":"yes"}`,
	} {
		require.Equal(t, http.StatusBadRequest, f.post(body).Code, name)
	}
	require.Empty(t, f.rows(t))
}

func TestStatusHandlerBadSecretCountsAuthFailure(t *testing.T) {
	f := newStatusFixture(t)
	failures := osctrldAuthFailures.WithLabelValues(f.env.Name)
	before := metricValue(t, failures)
	require.Equal(t, http.StatusForbidden, f.post(statusBody("wrong", nfNodeA, "exhausted", statusEvent)).Code)
	require.Equal(t, before+1, metricValue(t, failures))
	require.Empty(t, f.rows(t))
}

func TestStatusHandlerEventCountedAndAuditedOnce(t *testing.T) {
	f := newStatusFixture(t)
	c := osctrldRollbacks.WithLabelValues(f.env.Name, "flags", "exhausted")
	before := metricValue(t, c)
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.post(statusBody(f.env.Secret, nfNodeA, "exhausted", statusEvent)).Code)
	}
	require.Equal(t, before+1, metricValue(t, c))
	audits := f.rollbackAudits(t)
	require.Len(t, audits, 1)
	require.EqualValues(t, auditlog.LogTypeNode, audits[0].LogType)
	require.Equal(t, "osctrld rollback on node "+nfNodeA+" in env status-env: flags exhausted", audits[0].Line)
	require.EqualValues(t, f.env.ID, audits[0].EnvironmentID)
	require.Equal(t, "198.51.100.7", audits[0].SourceIP)
	// A new event for the same node counts again.
	again := "1760000000000000001:" + strings.Repeat("b", 64)
	require.Equal(t, http.StatusOK, f.post(statusBody(f.env.Secret, nfNodeA, "exhausted", again)).Code)
	require.Equal(t, before+2, metricValue(t, c))
	require.Len(t, f.rollbackAudits(t), 2)
}

func TestStatusHandlerDropsBogusStage(t *testing.T) {
	f := newStatusFixture(t)
	c := osctrldRollbacks.WithLabelValues(f.env.Name, "flags", "bogus")
	before := metricValue(t, c)
	require.Equal(t, http.StatusOK, f.post(statusBody(f.env.Secret, nfNodeA, "bogus", statusEvent)).Code)
	require.Equal(t, http.StatusOK, f.post(statusBody(f.env.Secret, nfNodeA, "exhausted", "not-an-event")).Code)
	require.Equal(t, before, metricValue(t, c))
	require.Empty(t, f.rollbackAudits(t))
	rows := f.rows(t)
	require.Len(t, rows, 1)
	require.Empty(t, rows[0].FlagsStage)
}

// downGauge returns the exported osctrld_osquery_down series by environment.
func downGauge(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range mfs {
		require.Equal(t, "osctrld_osquery_down", mf.GetName())
		for _, m := range mf.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			require.Equal(t, "environment", m.GetLabel()[0].GetName())
			out[m.GetLabel()[0].GetValue()] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestDownGaugePerEnvironment(t *testing.T) {
	f := newStatusFixture(t)
	now := time.Now()
	running, down := true, false
	rows := []nodeconfig.OsctrldStatus{
		{NodeUUID: nfNodeA, EnvironmentID: f.env.ID, OsqueryRunning: &down, ReportedAt: &now},
		{NodeUUID: "DDDDDDDD-DDDD-4DDD-8DDD-DDDDDDDDDDDD", EnvironmentID: f.env.ID, OsqueryRunning: &running, ReportedAt: &now},
		{NodeUUID: nfNodeOther, EnvironmentID: f.other.ID, OsqueryRunning: &down, ReportedAt: ptrTime(now.Add(-2 * nodeconfig.ReportFreshness))},
		{NodeUUID: "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE", EnvironmentID: 9999, OsqueryRunning: &down, ReportedAt: &now},
	}
	for i := range rows {
		require.NoError(t, f.db.Create(&rows[i]).Error)
	}
	require.Equal(t, map[string]float64{"status-env": 1, "status-other": 0},
		downGauge(t, NewOsctrldDownCollector(f.m, f.h.Envs)))
}

func TestDownGaugeSurvivesDBError(t *testing.T) {
	f := newStatusFixture(t)
	require.NoError(t, f.db.Migrator().DropTable(&nodeconfig.OsctrldStatus{}))
	require.NotPanics(t, func() {
		require.Empty(t, downGauge(t, NewOsctrldDownCollector(f.m, f.h.Envs)))
	})
}

func ptrTime(t time.Time) *time.Time { return &t }

// downCollectorClock is a manual clock for the collector.
type downCollectorClock struct{ t time.Time }

func (c *downCollectorClock) now() time.Time          { return c.t }
func (c *downCollectorClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func fakeDownReading() osctrldDownReading {
	return osctrldDownReading{counts: map[uint]int{1: 2}, envs: []environments.TLSEnvironment{{Name: "a"}}}
}

func TestDownCollectorTimeoutDoesNotBlockScrape(t *testing.T) {
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	clock := &downCollectorClock{t: time.Now()}
	c := newOsctrldDownCollector(func() (osctrldDownReading, error) {
		<-stall
		return osctrldDownReading{}, nil
	}, clock.now)
	c.timeout = 20 * time.Millisecond
	start := time.Now()
	require.Empty(t, downGauge(t, c))
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestDownCollectorCachesReadingForTTL(t *testing.T) {
	clock := &downCollectorClock{t: time.Now()}
	calls := 0
	c := newOsctrldDownCollector(func() (osctrldDownReading, error) {
		calls++
		return fakeDownReading(), nil
	}, clock.now)
	for i := 0; i < 5; i++ {
		require.Equal(t, map[string]float64{"a": 0}, downGauge(t, c))
	}
	require.Equal(t, 1, calls)
	clock.advance(osctrldDownTTL)
	downGauge(t, c)
	require.Equal(t, 2, calls)
}

func TestDownCollectorBacksOffAfterFailure(t *testing.T) {
	clock := &downCollectorClock{t: time.Now()}
	calls, fail := 0, true
	c := newOsctrldDownCollector(func() (osctrldDownReading, error) {
		calls++
		if fail {
			return osctrldDownReading{}, errors.New("db down")
		}
		return fakeDownReading(), nil
	}, clock.now)
	for i := 0; i < 3; i++ {
		require.Empty(t, downGauge(t, c))
	}
	require.Equal(t, 1, calls, "no DB call during the backoff")
	fail = false
	clock.advance(osctrldDownBackoff)
	require.Equal(t, map[string]float64{"a": 0}, downGauge(t, c))
	require.Equal(t, 2, calls)
}
