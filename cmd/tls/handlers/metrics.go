package handlers

import (
	"fmt"
	"sync"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

const (
	RequestPath   = "path"
	RequestMethod = "method"
	StatusCode    = "status_code"
	Environment   = "osctrl_env"
	RequestType   = "type"
	LogType       = "log_type"
)

var (
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_tls_request_duration_seconds",
		Help:    "The duration of requests",
		Buckets: []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1, 5},
	}, []string{RequestMethod, RequestPath, StatusCode})
	requestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_tls_request_size_bytes",
		Help:    "The size of requests",
		Buckets: []float64{100, 1000, 10000, 100000, 1000000},
	}, []string{Environment, RequestType})
	logProcessDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_tls_log_process_duration_seconds",
		Help:    "The duration of log/scheduled query processing",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
	}, []string{Environment, LogType})
	distributedQueryProcessingDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_tls_distributed_query_process_duration_seconds",
		Help:    "The duration of distributed query result processing",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
	}, []string{Environment})
	batchFlushDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_tls_batch_flush_duration_seconds",
		Help:    "The duration of batch data flushing to backend",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5},
	}, []string{"operation"})
	// osctrldAuthFailures counts wrong osctrld secrets per environment name
	// (only resolved environments, so cardinality stays bounded).
	osctrldAuthFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrld_auth_failures_total",
		Help: "osctrld requests rejected for a wrong environment secret",
	}, []string{"environment"})
	// osctrldRateLimited counts osctrld requests rejected with 429, by
	// route pattern and rate limit (osctrldAuth, osctrld, osctrldDownload).
	osctrldRateLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrld_rate_limited_total",
		Help: "osctrld requests rejected by a rate limit",
	}, []string{"route", "limit"})
	// osctrldAuthAuditDropped counts failed-secret audit entries dropped by
	// the per-environment audit cap.
	osctrldAuthAuditDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrld_auth_audit_dropped_total",
		Help: "osctrld failed-secret audit entries dropped by the per-environment cap",
	}, []string{"environment"})
	// osctrldRollbacks counts rollback events reported by osctrld, once per
	// event. Labels are the environment name and the validated stage.
	osctrldRollbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrld_rollbacks_total",
		Help: "osctrld rollbacks of flags or extensions reported by nodes",
	}, []string{"environment", "kind", "stage"})
	// osctrldUpgradeRollbacks counts osquery upgrades that osctrld rolled
	// back, once per event. The only label is the environment name.
	osctrldUpgradeRollbacks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrld_osquery_upgrade_rollbacks_total",
		Help: "osquery upgrades rolled back by osctrld and reported by nodes",
	}, []string{"environment"})
	osctrldDownDesc = prometheus.NewDesc("osctrld_osquery_down",
		"Nodes whose fresh osctrld report says osqueryd is not running", []string{"environment"}, nil)
	osctrldBehindDesc = prometheus.NewDesc("osctrld_osquery_behind",
		"Nodes whose fresh osctrld report shows an osquery version lower than their target", []string{"environment"}, nil)
	// DBDegraded is 1 when the DB health monitor reports the database
	// as degraded (caches are in stale-serve mode), 0 when healthy.
	dbDegraded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "osctrl_tls_db_degraded",
		Help: "1 when the DB health monitor reports the database as degraded and caches are in stale-serve mode, 0 when healthy.",
	})
)

func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(requestDuration)
	reg.MustRegister(requestSize)
	reg.MustRegister(logProcessDuration)
	reg.MustRegister(distributedQueryProcessingDuration)
	reg.MustRegister(batchFlushDuration)
	reg.MustRegister(dbDegraded)
	reg.MustRegister(osctrldAuthFailures)
	reg.MustRegister(osctrldRateLimited)
	reg.MustRegister(osctrldAuthAuditDropped)
	reg.MustRegister(osctrldRollbacks)
	reg.MustRegister(osctrldUpgradeRollbacks)
}

const (
	// osctrldDownTTL is how long a reading is served before the database is
	// asked again, so frequent scrapes cannot load it.
	osctrldDownTTL = 15 * time.Second
	// osctrldDownTimeout bounds one reading: a stalled database costs one
	// scrape this long, not every scrape (and the rest of the registry).
	osctrldDownTimeout = 5 * time.Second
	// osctrldDownBackoff is how long after a failed reading the database is
	// not asked again.
	osctrldDownBackoff = time.Minute
)

type osctrldDownReading struct {
	counts map[uint]int
	envs   []environments.TLSEnvironment
}

// osctrldDownCollector exports osctrld_osquery_down at scrape time, for every
// known environment (0 when none is down). Like the vulns collector it reuses
// a reading for a TTL, bounds the read with a timeout and backs off after a
// failure; a failed or timed-out read exports nothing rather than zeros.
type osctrldDownCollector struct {
	load    func() (osctrldDownReading, error)
	now     func() time.Time
	timeout time.Duration
	what    string // names the reading in log messages

	mu      sync.Mutex
	readAt  time.Time
	reading *osctrldDownReading
	failAt  time.Time // last failed read; zero when the last read worked
}

// NewOsctrldDownCollector returns the collector for osctrld_osquery_down.
func NewOsctrldDownCollector(flags *nodeconfig.FlagsManager, envs *environments.EnvManager) prometheus.Collector {
	return newOsctrldDownCollector(func() (osctrldDownReading, error) {
		counts, err := flags.CountDown(time.Now())
		if err != nil {
			return osctrldDownReading{}, err
		}
		list, err := envs.All()
		return osctrldDownReading{counts: counts, envs: list}, err
	}, time.Now)
}

func newOsctrldDownCollector(load func() (osctrldDownReading, error), now func() time.Time) *osctrldDownCollector {
	return &osctrldDownCollector{load: load, now: now, timeout: osctrldDownTimeout, what: "osctrld down nodes"}
}

func (c *osctrldDownCollector) Describe(ch chan<- *prometheus.Desc) { ch <- osctrldDownDesc }

func (c *osctrldDownCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.read()
	if r == nil {
		return
	}
	for _, e := range r.envs {
		ch <- prometheus.MustNewConstMetric(osctrldDownDesc, prometheus.GaugeValue, float64(r.counts[e.ID]), e.Name)
	}
}

// osctrldBehindCollector exports osctrld_osquery_behind with the same
// cache, timeout, backoff and failure behavior as the down collector, whose
// reading it reuses.
type osctrldBehindCollector struct{ *osctrldDownCollector }

// NewOsctrldBehindCollector returns the collector for osctrld_osquery_behind.
func NewOsctrldBehindCollector(m *osqueryversions.Manager, envs *environments.EnvManager) prometheus.Collector {
	return newOsctrldBehindCollector(func() (osctrldDownReading, error) {
		counts, err := m.CountBehind(time.Now(), nodeconfig.ReportFreshness)
		if err != nil {
			return osctrldDownReading{}, err
		}
		list, err := envs.All()
		return osctrldDownReading{counts: counts, envs: list}, err
	}, time.Now)
}

func newOsctrldBehindCollector(load func() (osctrldDownReading, error), now func() time.Time) *osctrldBehindCollector {
	c := newOsctrldDownCollector(load, now)
	c.what = "osctrld behind nodes"
	return &osctrldBehindCollector{c}
}

func (c *osctrldBehindCollector) Describe(ch chan<- *prometheus.Desc) { ch <- osctrldBehindDesc }

func (c *osctrldBehindCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.read()
	if r == nil {
		return
	}
	for _, e := range r.envs {
		ch <- prometheus.MustNewConstMetric(osctrldBehindDesc, prometheus.GaugeValue, float64(r.counts[e.ID]), e.Name)
	}
}

func (c *osctrldDownCollector) read() *osctrldDownReading {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.reading != nil && now.Sub(c.readAt) < osctrldDownTTL {
		return c.reading
	}
	if !c.failAt.IsZero() && now.Sub(c.failAt) < osctrldDownBackoff {
		return nil
	}
	// The managers take no context, so the bound is enforced here; a stalled
	// read is abandoned (at most one at a time, because of the backoff).
	type result struct {
		r   osctrldDownReading
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- result{err: fmt.Errorf("panic reading %s: %v", c.what, p)}
			}
		}()
		r, err := c.load()
		done <- result{r, err}
	}()
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case res := <-done:
		if res.err != nil {
			log.Err(res.err).Msgf("error reading %s", c.what)
			c.failAt = now
			return nil
		}
		c.reading, c.readAt, c.failAt = &res.r, now, time.Time{}
		return c.reading
	case <-timer.C:
		log.Warn().Msgf("timeout reading %s", c.what)
		c.failAt = now
		return nil
	}
}

// SetDBDegraded updates the db_degraded gauge. Called by the DB
// health monitor via its OnChange callback. Safe to call even when
// metrics are not registered (the gauge is a no-op until
// RegisterMetrics runs).
func SetDBDegraded(degraded bool) {
	if degraded {
		dbDegraded.Set(1)
	} else {
		dbDegraded.Set(0)
	}
}
