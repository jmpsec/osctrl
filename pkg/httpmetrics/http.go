// Package httpmetrics adds low-cardinality HTTP request metrics to the
// osctrl-api server. It is deliberately separate from the TLS-specific
// handler metrics so both services can share a naming convention without
// importing each other's packages.
package httpmetrics

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrl_api_requests_total",
		Help: "Total HTTP requests handled by osctrl-api",
	}, []string{"method", "route", "status"})
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "osctrl_api_request_duration_seconds",
		Help:    "HTTP request duration for osctrl-api",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "route", "status"})
	requestsInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "osctrl_api_requests_in_flight",
		Help: "HTTP requests currently being served by osctrl-api",
	})
	retentionPrunedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "osctrl_api_retention_pruned_total",
		Help: "Rows or objects pruned by the osctrl-api retention worker, by data class",
	}, []string{"class"})
)

// Register adds the HTTP metrics to reg. Call once during startup when metrics
// are enabled; the middleware itself is safe to use before or after.
func Register(reg prometheus.Registerer) {
	reg.MustRegister(requestsTotal, requestDuration, requestsInFlight, retentionPrunedTotal)
}

// RecordRetentionPruned adds one retention sweep's count for a data class.
// Recording is safe before Register: the counter simply becomes visible once
// the metrics listener registers it.
func RecordRetentionPruned(class string, count int64) {
	if count > 0 {
		retentionPrunedTotal.WithLabelValues(class).Add(float64(count))
	}
}

// Middleware records method, matched route pattern, final status and duration
// for every request. It preserves http.Flusher, http.Hijacker and
// http.Pusher so SSE streams, downloads and WebSocket-style upgrades keep
// working through the wrapper.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		requestsInFlight.Inc()
		defer requestsInFlight.Dec()

		next.ServeHTTP(recorder, r)

		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		status := strconv.Itoa(recorder.status)
		requestsTotal.WithLabelValues(r.Method, route, status).Inc()
		requestDuration.WithLabelValues(r.Method, route, status).Observe(time.Since(start).Seconds())
	})
}

// statusRecorder captures the status code without changing the response.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("httpmetrics: ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

func (w *statusRecorder) Push(target string, opts *http.PushOptions) error {
	p, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}

func (w *statusRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}
