package handlers

import "github.com/prometheus/client_golang/prometheus"

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
