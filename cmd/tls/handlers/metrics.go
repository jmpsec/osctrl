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
)

func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(requestDuration)
	reg.MustRegister(requestSize)
	reg.MustRegister(logProcessDuration)
	reg.MustRegister(distributedQueryProcessingDuration)
	reg.MustRegister(batchFlushDuration)
}
