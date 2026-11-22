package httpmetrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestMiddlewareRecordsRouteStatusAndDuration(t *testing.T) {
	requestsTotal.Reset()
	requestDuration.Reset()
	requestsInFlight.Set(0)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})

	rr := httptest.NewRecorder()
	Middleware(mux).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, float64(1), testutil.ToFloat64(requestsTotal.WithLabelValues("GET", "GET /x", "201")))
	require.Equal(t, float64(0), testutil.ToFloat64(requestsInFlight))
	require.Equal(t, 1, testutil.CollectAndCount(requestDuration))
}

func TestMiddlewareLabelsUnmatchedRoutesWithoutPathCardinality(t *testing.T) {
	requestsTotal.Reset()
	rr := httptest.NewRecorder()
	Middleware(http.NewServeMux()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))

	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Equal(t, float64(1), testutil.ToFloat64(requestsTotal.WithLabelValues("GET", "unmatched", "404")))
}

func TestMiddlewarePreservesFlusher(t *testing.T) {
	mux := http.NewServeMux()
	flushed := false
	mux.HandleFunc("GET /flush", func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		require.True(t, ok)
		f.Flush()
		flushed = true
	})

	rr := httptest.NewRecorder()
	Middleware(mux).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/flush", nil))
	require.True(t, flushed)
}

func TestRegisterOnlyOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	require.NotPanics(t, func() { Register(reg) })
}
