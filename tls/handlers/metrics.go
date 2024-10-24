package handlers

import "github.com/prometheus/client_golang/prometheus"

const (
	RequestPath   = "path"
	RequestMethod = "method"
	StatusCode    = "status_code"
	Environment   = "env"
	RequestType   = "type"
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
)

func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(requestDuration)
	reg.MustRegister(requestSize)
}
