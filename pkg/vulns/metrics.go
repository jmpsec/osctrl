package vulns

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// metrics.go — Prometheus gauges for vulnerability monitoring. osctrl-tls
// exports them (it has the metrics server); the worker runs in osctrl-api,
// so the numbers come from the shared database. A reading is reused for
// metricsTTL so frequent scrapes cannot load the database.

const metricsTTL = time.Minute

var (
	descAdvisories  = prometheus.NewDesc("osctrl_vuln_advisories", "Stored advisories.", nil, nil)
	descLastSuccess = prometheus.NewDesc("osctrl_vuln_feed_last_success_timestamp_seconds", "Last successful sync of each advisory feed.", []string{"source"}, nil)
	descOpen        = prometheus.NewDesc("osctrl_vuln_findings_open", "Open findings.", []string{"confidence"}, nil)
	descResolved    = prometheus.NewDesc("osctrl_vuln_findings_resolved", "Resolved findings still kept.", nil, nil)
	descPending     = prometheus.NewDesc("osctrl_vuln_nodes_pending_match", "Nodes whose inventory changed since they were last matched.", nil, nil)
	descNotAssessed = prometheus.NewDesc("osctrl_vuln_packages_not_assessed", "Installed packages that could not be assessed.", nil, nil)
)

// RegisterMetrics registers the vulnerability gauges.
func RegisterMetrics(reg prometheus.Registerer, db *gorm.DB) {
	reg.MustRegister(newMetricsCollector(db, time.Now))
}

type metricsReading struct {
	advisories, resolved, pending, notAssessed int64
	open                                       map[string]int64     // confidence → count
	lastSuccess                                map[string]time.Time // source → time
}

type metricsCollector struct {
	db  *gorm.DB
	now func() time.Time

	mu      sync.Mutex
	readAt  time.Time
	reading *metricsReading
}

func newMetricsCollector(db *gorm.DB, now func() time.Time) *metricsCollector {
	return &metricsCollector{db: db, now: now}
}

// Describe implements prometheus.Collector.
func (c *metricsCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descAdvisories, descLastSuccess, descOpen, descResolved, descPending, descNotAssessed} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. A failed read exports nothing
// rather than zeros that would read as "no findings".
func (c *metricsCollector) Collect(ch chan<- prometheus.Metric) {
	r := c.read()
	if r == nil {
		return
	}
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	gauge(descAdvisories, float64(r.advisories))
	for source, at := range r.lastSuccess {
		gauge(descLastSuccess, float64(at.Unix()), source)
	}
	for _, conf := range []string{ConfidenceConfirmed, ConfidencePossible} {
		gauge(descOpen, float64(r.open[conf]), conf)
	}
	gauge(descResolved, float64(r.resolved))
	gauge(descPending, float64(r.pending))
	gauge(descNotAssessed, float64(r.notAssessed))
}

func (c *metricsCollector) read() *metricsReading {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.reading != nil && now.Sub(c.readAt) < metricsTTL {
		return c.reading
	}
	r, err := c.query(now)
	if err != nil {
		log.Warn().Err(err).Msg("vulns: reading metrics failed")
		return nil
	}
	c.reading, c.readAt = r, now
	return r
}

func (c *metricsCollector) query(now time.Time) (*metricsReading, error) {
	r := &metricsReading{open: map[string]int64{}, lastSuccess: map[string]time.Time{}}
	if err := c.db.Model(&Advisory{}).Count(&r.advisories).Error; err != nil {
		return nil, err
	}
	var open []struct {
		Confidence string
		Total      int64
	}
	if err := c.db.Model(&Finding{}).Select("confidence, COUNT(*) AS total").
		Where("resolved_at IS NULL").Group("confidence").Scan(&open).Error; err != nil {
		return nil, err
	}
	for _, o := range open {
		r.open[o.Confidence] = o.Total
	}
	if err := c.db.Model(&Finding{}).Where("resolved_at IS NOT NULL").Count(&r.resolved).Error; err != nil {
		return nil, err
	}
	// The worker's queue: the nodes matchDirty would pick.
	if err := c.db.Model(&NodeState{}).
		Where("(matched_at IS NULL OR matched_at < inventory_at) AND inventory_at > ?", now.Add(-staleNodeAge)).
		Count(&r.pending).Error; err != nil {
		return nil, err
	}
	if err := c.db.Model(&NodeState{}).Select("COALESCE(SUM(not_assessed), 0)").Scan(&r.notAssessed).Error; err != nil {
		return nil, err
	}
	var states []SyncState
	if err := c.db.Where("last_success IS NOT NULL").Find(&states).Error; err != nil {
		return nil, err
	}
	for _, s := range states {
		r.lastSuccess[s.Source] = *s.LastSuccess
	}
	return r, nil
}
