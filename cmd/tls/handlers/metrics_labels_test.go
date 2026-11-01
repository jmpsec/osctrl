package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Distinct caller-chosen {env} values must not create new duration label sets.
func TestPrometheusMiddlewareLabelsByRoutePattern(t *testing.T) {
	h := &HandlersTLS{}
	mux := http.NewServeMux()
	mux.Handle("POST /{env}/config", h.PrometheusMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})))
	before := countSeries(requestDuration)
	for i := range 50 {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, fmt.Sprintf("/env-%d/config", i), nil))
	}
	require.LessOrEqual(t, countSeries(requestDuration)-before, 1)
	require.Equal(t, "other", logTypeLabel("attacker-chosen"))
	require.Equal(t, "result", logTypeLabel("result"))
}

func countSeries(c prometheus.Collector) int {
	ch := make(chan prometheus.Metric, 1024)
	c.Collect(ch)
	close(ch)
	return len(ch)
}
