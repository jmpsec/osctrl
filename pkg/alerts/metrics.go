package alerts

import (
	"github.com/prometheus/client_golang/prometheus"
)

// metrics.go — Prometheus exporter for the dispatch worker. Uses a
// custom collector so the counters stay plain atomics on the hot path;
// the registry reads them on scrape. Queue depth is read from the
// channel, which is safe (len on a channel is defined).

// RegisterWorkerMetrics registers a collector for the worker's
// counters. Call once per process with the live worker; the collector
// reads the same atomics the hot path bumps, so there is no locking
// between scrape and dispatch.
func RegisterWorkerMetrics(reg prometheus.Registerer, w *Worker) {
	reg.MustRegister(&workerCollector{w: w})
}

type workerCollector struct {
	w *Worker
}

var (
	_ prometheus.Collector = (*workerCollector)(nil)
)

// Describe implements prometheus.Collector.
func (c *workerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc("matched", "Hits accepted into the dispatch queue.")
	ch <- c.desc("dropped", "Hits dropped because the dispatch queue was full.")
	ch <- c.desc("dispatched", "Hits successfully dispatched to a channel.")
	ch <- c.desc("collapsed", "Hits suppressed by the cooldown gate.")
	ch <- c.desc("failed", "Dispatch attempts that returned an error.")
	ch <- c.desc("queue_depth", "Hits currently waiting in the dispatch queue.")
}

// Collect implements prometheus.Collector.
func (c *workerCollector) Collect(ch chan<- prometheus.Metric) {
	if c.w == nil {
		return
	}
	ch <- c.gauge("matched", float64(c.w.metrics.Matched.Load()))
	ch <- c.gauge("dropped", float64(c.w.metrics.Dropped.Load()))
	ch <- c.gauge("dispatched", float64(c.w.metrics.Dispatched.Load()))
	ch <- c.gauge("collapsed", float64(c.w.metrics.Collapsed.Load()))
	ch <- c.gauge("failed", float64(c.w.metrics.Failed.Load()))
	ch <- c.gauge("queue_depth", float64(c.w.QueueDepth()))
}

func (c *workerCollector) name(suffix string) string {
	return "osctrl_alerts_" + suffix
}

func (c *workerCollector) desc(suffix, help string) *prometheus.Desc {
	return prometheus.NewDesc(c.name(suffix), help, nil, nil)
}

// gauge emits a raw value; counters are Uint64 atomics that never
// decrease, so presenting them as gauges preserves monotonicity for
// rate() while avoiding the counter-increment coupling.
func (c *workerCollector) gauge(suffix string, v float64) prometheus.Metric {
	return prometheus.MustNewConstMetric(c.desc(suffix, c.helpFor(suffix)), prometheus.GaugeValue, v)
}

func (c *workerCollector) helpFor(suffix string) string {
	switch suffix {
	case "matched":
		return "Hits accepted into the dispatch queue."
	case "dropped":
		return "Hits dropped because the dispatch queue was full."
	case "dispatched":
		return "Hits successfully dispatched to a channel."
	case "collapsed":
		return "Hits suppressed by the cooldown gate."
	case "failed":
		return "Dispatch attempts that returned an error."
	case "queue_depth":
		return "Hits currently waiting in the dispatch queue."
	default:
		return suffix
	}
}
