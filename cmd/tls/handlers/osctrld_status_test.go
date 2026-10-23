package handlers

import (
	"bytes"
	"errors"
	"fmt"
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
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type statusFixture struct {
	h          *HandlersTLS
	db         *gorm.DB
	m          *nodeconfig.FlagsManager
	ov         *osqueryversions.Manager
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
	f.ov, err = osqueryversions.NewManager(db)
	require.NoError(t, err)
	f.h = CreateHandlersTLS(WithEnvs(envs), WithNodes(nodesRepo), WithFlagsOverrides(f.m), WithAuditLog(audit), WithOsqueryVersions(f.ov),
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

// failOn makes every statement on table that contains substr fail, for the
// rest of the test.
func (f *statusFixture) failOn(t *testing.T, name, table, substr string) {
	t.Helper()
	fail := func(tx *gorm.DB) {
		if tx.Statement.Table == table && strings.Contains(fmt.Sprint(tx.Statement.Clauses, tx.Statement.Dest), substr) {
			_ = tx.AddError(errors.New("injected db error"))
		}
	}
	require.NoError(t, f.db.Callback().Query().Before("gorm:query").Register(name+"q", fail))
	require.NoError(t, f.db.Callback().Update().Before("gorm:update").Register(name+"u", fail))
}

func TestStatusHandlerNodeLookupDBErrorIs500(t *testing.T) {
	f := newStatusFixture(t)
	f.failOn(t, "nodes", "osquery_nodes", "")
	w := f.post(statusBody(f.env.Secret, nfNodeA, "exhausted", statusEvent))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Empty(t, w.Body.String())
	require.Empty(t, f.rows(t))
}

func TestStatusHandlerUnknownAndOtherEnvNodeAnswerIdentically(t *testing.T) {
	f := newStatusFixture(t)
	a := f.post(statusBody(f.env.Secret, nfNodeOther, "none", ""))
	b := f.post(statusBody(f.env.Secret, "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC", "none", ""))
	require.Equal(t, http.StatusBadRequest, a.Code)
	require.Equal(t, a.Code, b.Code)
	require.Equal(t, a.Body.String(), b.Body.String())
	require.Empty(t, a.Body.String())
}

func TestStatusHandlerPartialRecordFailureStillCountsAndAudits(t *testing.T) {
	f := newStatusFixture(t)
	f.failOn(t, "ext", "node_osctrld_status", "extensions_event_id")
	body := `{"secret":"` + f.env.Secret + `","uuid":"` + nfNodeA + `","osquery_running":true,` +
		`"flags":{"stage":"exhausted","event_id":"` + statusEvent + `"},"extensions":{"stage":"exhausted","event_id":"` + statusEvent + `"}}`
	c := osctrldRollbacks.WithLabelValues(f.env.Name, "flags", "exhausted")
	before := metricValue(t, c)
	require.Equal(t, http.StatusInternalServerError, f.post(body).Code)
	require.Equal(t, before+1, metricValue(t, c))
	require.Len(t, f.rollbackAudits(t), 1)
	// Retry: the flags event is stored already, so it is not counted twice.
	require.Equal(t, http.StatusInternalServerError, f.post(body).Code)
	require.Equal(t, before+1, metricValue(t, c))
	require.Len(t, f.rollbackAudits(t), 1)
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

func upgradeBody(secret, uuid, upgrade string) string {
	return `{"secret":"` + secret + `","uuid":"` + uuid + `","osquery_running":true,` +
		`"flags":{"stage":"none","event_id":""},"extensions":{"stage":"none","event_id":""},"upgrade":` + upgrade + `}`
}

func (f *statusFixture) upgradeAudits(t *testing.T) []auditlog.AuditLog {
	t.Helper()
	var rows []auditlog.AuditLog
	require.NoError(t, f.db.Where("line LIKE ?", "osctrld osquery upgrade rolled back%").Find(&rows).Error)
	return rows
}

func TestStatusHandlerUpgradeRollbackCountedAndAuditedOnce(t *testing.T) {
	f := newStatusFixture(t)
	c := osctrldUpgradeRollbacks.WithLabelValues(f.env.Name)
	before := metricValue(t, c)
	body := upgradeBody(f.env.Secret, nfNodeA, `{"result":"rejected","version":"5.13.0","reason":"version_not_reported","event_id":"`+statusEvent+`"}`)
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.post(body).Code)
	}
	require.Equal(t, before+1, metricValue(t, c))
	audits := f.upgradeAudits(t)
	require.Len(t, audits, 1)
	require.EqualValues(t, auditlog.LogTypeNode, audits[0].LogType)
	require.Equal(t, "osctrld osquery upgrade rolled back on node "+nfNodeA+" in env status-env: 5.13.0 (version_not_reported)", audits[0].Line)
	require.Equal(t, "198.51.100.7", audits[0].SourceIP)
	require.Empty(t, f.rollbackAudits(t))
}

func TestStatusHandlerUpgradeOKDoesNotCount(t *testing.T) {
	f := newStatusFixture(t)
	c := osctrldUpgradeRollbacks.WithLabelValues(f.env.Name)
	before := metricValue(t, c)
	require.Equal(t, http.StatusOK, f.post(upgradeBody(f.env.Secret, nfNodeA, `{"result":"ok","version":"5.13.0"}`)).Code)
	require.Equal(t, before, metricValue(t, c))
	require.Empty(t, f.upgradeAudits(t))
	rows := f.rows(t)
	require.Len(t, rows, 1)
	require.Equal(t, "ok", rows[0].UpgradeResult)
}

// behindGauge returns the exported osctrld_osquery_behind series by environment.
func behindGauge(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range mfs {
		require.Equal(t, "osctrld_osquery_behind", mf.GetName())
		for _, m := range mf.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			require.Equal(t, "environment", m.GetLabel()[0].GetName())
			out[m.GetLabel()[0].GetValue()] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestBehindGaugePerEnvironment(t *testing.T) {
	f := newStatusFixture(t)
	vm, err := osqueryversions.NewManager(f.db)
	require.NoError(t, err)
	require.NoError(t, vm.PutEntries("5.13.0", []osqueryversions.DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: strings.Repeat("a", 64)}}, "t"))
	_, err = vm.SetEnvTarget(f.env.ID, "5.13.0", "t")
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", nfNodeA).Update("osquery_version", "5.12.1").Error)
	require.NoError(t, f.db.Create(&nodeconfig.OsctrldStatus{NodeUUID: nfNodeA, EnvironmentID: f.env.ID, ReportedAt: &now}).Error)
	require.Equal(t, map[string]float64{"status-env": 1, "status-other": 0},
		behindGauge(t, NewOsctrldBehindCollector(vm, f.h.Envs)))
}

func TestBehindCollectorCachesAndBacksOff(t *testing.T) {
	clock := &downCollectorClock{t: time.Now()}
	calls, fail := 0, true
	c := newOsctrldBehindCollector(func() (osctrldDownReading, error) {
		calls++
		if fail {
			return osctrldDownReading{}, errors.New("db down")
		}
		return osctrldDownReading{counts: map[uint]int{1: 2}, envs: []environments.TLSEnvironment{{Name: "a", ID: 1}}}, nil
	}, clock.now)
	for i := 0; i < 3; i++ {
		require.Empty(t, behindGauge(t, c))
	}
	require.Equal(t, 1, calls, "no DB call during the backoff")
	fail = false
	clock.advance(osctrldDownBackoff)
	for i := 0; i < 3; i++ {
		require.Equal(t, map[string]float64{"a": 2}, behindGauge(t, c))
	}
	require.Equal(t, 2, calls, "reading is cached for the TTL")
	clock.advance(osctrldDownTTL)
	behindGauge(t, c)
	require.Equal(t, 3, calls)
}

func TestBehindCollectorTimeoutDoesNotBlock(t *testing.T) {
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	c := newOsctrldBehindCollector(func() (osctrldDownReading, error) {
		<-stall
		return osctrldDownReading{}, nil
	}, time.Now)
	c.timeout = 20 * time.Millisecond
	start := time.Now()
	require.Empty(t, behindGauge(t, c))
	require.Less(t, time.Since(start), 2*time.Second)
}

func (f *statusFixture) startRollout(t *testing.T) *osqueryversions.Rollout {
	t.Helper()
	require.NoError(t, f.ov.PutEntries("5.13.0", []osqueryversions.DigestEntry{{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: strings.Repeat("b", 64)}}, "t"))
	_, r, err := f.ov.SetEnvTargetRollout(f.env.ID, "5.13.0", "t", []string{nfNodeA}, time.Now())
	require.NoError(t, err)
	return r
}

func (f *statusFixture) rollbackReport(secret, uuid, requestID, reason string) string {
	return upgradeBody(secret, uuid, `{"result":"rejected","version":"5.13.0","reason":"`+reason+`","request_id":"`+requestID+`","event_id":"`+statusEvent+`"}`)
}

func (f *statusFixture) pausedAudits(t *testing.T) []auditlog.AuditLog {
	t.Helper()
	var rows []auditlog.AuditLog
	require.NoError(t, f.db.Where("line LIKE ?", "osquery rollout paused%").Find(&rows).Error)
	return rows
}

func (f *statusFixture) rollout(t *testing.T) *osqueryversions.Rollout {
	t.Helper()
	r, err := f.ov.GetRollout(f.env.ID)
	require.NoError(t, err)
	return r
}

func TestStatusHandlerRollbackPausesCurrentRollout(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", nfNodeA).Update("hostname", "web-1").Error)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "version_not_reported")).Code)
	got := f.rollout(t)
	require.Equal(t, osqueryversions.RolloutPaused, got.State)
	require.Equal(t, "web-1", got.PausedHost)
	require.Equal(t, "version_not_reported", got.PausedReason)
	audits := f.pausedAudits(t)
	require.Len(t, audits, 1)
	require.EqualValues(t, auditlog.LogTypeEnvironment, audits[0].LogType)
	require.EqualValues(t, f.env.ID, audits[0].EnvironmentID)
}

func TestStatusHandlerRollbackOfOtherRequestIDDoesNotPause(t *testing.T) {
	f := newStatusFixture(t)
	f.startRollout(t)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReport(f.env.Secret, nfNodeA, strings.Repeat("c", 32), "version_not_reported")).Code)
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Empty(t, f.pausedAudits(t))
	// A report without a request id (a pin) never pauses either.
	require.Equal(t, http.StatusOK, f.post(upgradeBody(f.env.Secret, nfNodeA, `{"result":"rejected","version":"5.13.0","reason":"install_failed","event_id":"`+statusEvent+`"}`)).Code)
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
}

func TestStatusHandlerSkippedNeverPauses(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	require.Equal(t, http.StatusOK, f.post(upgradeBody(f.env.Secret, nfNodeA, `{"result":"skipped","version":"5.13.0","reason":"rollout_pending","request_id":"`+r.RequestID+`"}`)).Code)
	require.Equal(t, http.StatusOK, f.post(upgradeBody(f.env.Secret, nfNodeA, `{"result":"skipped","reason":"rollout_paused","request_id":"`+r.RequestID+`"}`)).Code)
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Empty(t, f.pausedAudits(t))
}

func TestStatusHandlerRepeatedRollbackPausesOnceAndAuditsOnce(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	body := f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "digest_mismatch")
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.post(body).Code)
	}
	require.Equal(t, osqueryversions.RolloutPaused, f.rollout(t).State)
	require.Len(t, f.pausedAudits(t), 1)
}

func TestStatusHandlerPauseRepairedByLaterReport(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	body := f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "digest_mismatch")
	f.failOn(t, "rollouts", "osquery_rollouts", "")
	require.Equal(t, http.StatusInternalServerError, f.post(body).Code)
	require.NoError(t, f.db.Callback().Query().Remove("rolloutsq"))
	require.NoError(t, f.db.Callback().Update().Remove("rolloutsu"))
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Equal(t, http.StatusOK, f.post(body).Code)
	require.Equal(t, osqueryversions.RolloutPaused, f.rollout(t).State)
	require.Len(t, f.pausedAudits(t), 1)
	require.Len(t, f.upgradeAudits(t), 1, "the rollback itself is not counted twice")
}

func TestStatusHandlerPausedHostCleanedAndBounded(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	require.NoError(t, f.db.Model(&nodes.OsqueryNode{}).Where("uuid = ?", nfNodeA).Update("hostname", "ev\nil"+strings.Repeat("x", 400)).Error)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "digest_mismatch")).Code)
	got := f.rollout(t)
	require.Len(t, []rune(got.PausedHost), 255)
	require.True(t, strings.HasPrefix(got.PausedHost, "evilxxx"))
	audits := f.pausedAudits(t)
	require.Len(t, audits, 1)
	require.NotContains(t, audits[0].Line, "\n")
	require.Contains(t, audits[0].Line, got.PausedHost)
}

func TestStatusHandlerRollbackAfterAbortDoesNotPause(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	_, err := f.ov.AbortRollout(f.env.ID, "t", time.Now())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "digest_mismatch")).Code)
	require.Equal(t, osqueryversions.RolloutAborted, f.rollout(t).State)
	require.Empty(t, f.pausedAudits(t))
}

func TestStatusHandlerOtherEnvironmentNodeCannotPause(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	require.Equal(t, http.StatusBadRequest, f.post(f.rollbackReport(f.env.Secret, nfNodeOther, r.RequestID, "digest_mismatch")).Code)
	// The other environment's own node, reporting the first environment's request id.
	req := httptest.NewRequest(http.MethodPost, "/osctrld-status", bytes.NewBufferString(f.rollbackReport(f.other.Secret, nfNodeOther, r.RequestID, "digest_mismatch")))
	req.SetPathValue("env", f.other.UUID)
	w := httptest.NewRecorder()
	f.h.StatusHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Empty(t, f.pausedAudits(t))
}

func TestStatusHandlerWithoutOsqueryVersionsManager(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	f.h.OsqueryVersions = nil
	require.Equal(t, http.StatusOK, f.post(f.rollbackReport(f.env.Secret, nfNodeA, r.RequestID, "digest_mismatch")).Code)
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Len(t, f.upgradeAudits(t), 1)
}

// pausedGauge returns the exported osctrld_osquery_rollout_paused series by environment.
func pausedGauge(t *testing.T, c prometheus.Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(c))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	out := map[string]float64{}
	for _, mf := range mfs {
		require.Equal(t, "osctrld_osquery_rollout_paused", mf.GetName())
		for _, m := range mf.GetMetric() {
			require.Len(t, m.GetLabel(), 1)
			require.Equal(t, "environment", m.GetLabel()[0].GetName())
			out[m.GetLabel()[0].GetValue()] = m.GetGauge().GetValue()
		}
	}
	return out
}

func TestRolloutPausedGaugePerEnvironment(t *testing.T) {
	f := newStatusFixture(t)
	vm, err := osqueryversions.NewManager(f.db)
	require.NoError(t, err)
	require.NoError(t, f.db.Create(&osqueryversions.Rollout{EnvironmentID: f.env.ID, RequestID: "p", Version: "5.13.0",
		State: osqueryversions.RolloutPaused, Thresholds: "[]"}).Error)
	require.Equal(t, map[string]float64{"status-env": 1, "status-other": 0},
		pausedGauge(t, NewOsctrldRolloutPausedCollector(vm, f.h.Envs)))
}

func TestRolloutPausedCollectorCachesAndBacksOff(t *testing.T) {
	clock := &downCollectorClock{t: time.Now()}
	calls, fail := 0, true
	c := newOsctrldRolloutPausedCollector(func() (osctrldDownReading, error) {
		calls++
		if fail {
			return osctrldDownReading{}, errors.New("db down")
		}
		return osctrldDownReading{counts: map[uint]int{1: 1}, envs: []environments.TLSEnvironment{{Name: "a", ID: 1}, {Name: "b", ID: 2}}}, nil
	}, clock.now)
	for i := 0; i < 3; i++ {
		require.Empty(t, pausedGauge(t, c))
	}
	require.Equal(t, 1, calls, "no DB call during the backoff")
	fail = false
	clock.advance(osctrldDownBackoff)
	for i := 0; i < 3; i++ {
		require.Equal(t, map[string]float64{"a": 1, "b": 0}, pausedGauge(t, c))
	}
	require.Equal(t, 2, calls, "reading is cached for the TTL")
	clock.advance(osctrldDownTTL)
	pausedGauge(t, c)
	require.Equal(t, 3, calls)
}

func TestRolloutPausedCollectorTimeoutDoesNotBlock(t *testing.T) {
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	c := newOsctrldRolloutPausedCollector(func() (osctrldDownReading, error) {
		<-stall
		return osctrldDownReading{}, nil
	}, time.Now)
	c.timeout = 20 * time.Millisecond
	start := time.Now()
	require.Empty(t, pausedGauge(t, c))
	require.Less(t, time.Since(start), 2*time.Second)
}

func (f *statusFixture) rollbackReportEvent(requestID, event string) string {
	return upgradeBody(f.env.Secret, nfNodeA, `{"result":"rejected","version":"5.13.0","reason":"digest_mismatch","request_id":"`+requestID+`","event_id":"`+event+`"}`)
}

var statusEvent2 = "1760000000000000001:" + strings.Repeat("b", 64)

func TestStatusHandlerResumeIsNotUndoneByReReportedRollback(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	old := f.rollbackReportEvent(r.RequestID, statusEvent)
	require.Equal(t, http.StatusOK, f.post(old).Code)
	require.Equal(t, osqueryversions.RolloutPaused, f.rollout(t).State)
	time.Sleep(5 * time.Millisecond)
	_, err := f.ov.ResumeRollout(f.env.ID, "op", time.Now())
	require.NoError(t, err)
	// osctrld keeps reporting the same rejected result.
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusOK, f.post(old).Code)
	}
	require.Equal(t, osqueryversions.RolloutRunning, f.rollout(t).State)
	require.Len(t, f.pausedAudits(t), 1, "no second pause audit")

	// A new rollback after the resume pauses again.
	time.Sleep(5 * time.Millisecond)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReportEvent(r.RequestID, statusEvent2)).Code)
	require.Equal(t, osqueryversions.RolloutPaused, f.rollout(t).State)
	require.Len(t, f.pausedAudits(t), 2)
}

func TestStatusHandlerPauseFailureAfterResumeIsRepairedByRetry(t *testing.T) {
	f := newStatusFixture(t)
	r := f.startRollout(t)
	require.Equal(t, http.StatusOK, f.post(f.rollbackReportEvent(r.RequestID, statusEvent)).Code)
	time.Sleep(5 * time.Millisecond)
	_, err := f.ov.ResumeRollout(f.env.ID, "op", time.Now())
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)
	body := f.rollbackReportEvent(r.RequestID, statusEvent2)
	f.failOn(t, "rollouts", "osquery_rollouts", "")
	require.Equal(t, http.StatusInternalServerError, f.post(body).Code)
	require.NoError(t, f.db.Callback().Query().Remove("rolloutsq"))
	require.NoError(t, f.db.Callback().Update().Remove("rolloutsu"))
	require.Equal(t, http.StatusOK, f.post(body).Code)
	require.Equal(t, osqueryversions.RolloutPaused, f.rollout(t).State)
}
