package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func installTestTracer(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	enabled.Store(true)
	t.Cleanup(func() {
		enabled.Store(false)
		_ = provider.Shutdown(context.Background())
	})
	return exporter
}

func TestSetupDisabledIsNoOp(t *testing.T) {
	enabled.Store(false)
	shutdown, err := Setup(context.Background(), Config{Enabled: false})
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	require.False(t, Enabled())
}

func TestSetupRejectsInvalidSampleRatio(t *testing.T) {
	_, err := Setup(context.Background(), Config{Enabled: true, SampleRatio: 1.5})
	require.Error(t, err)
}

func TestHTTPMiddlewareRecordsRouteAndStatus(t *testing.T) {
	exporter := installTestTracer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	rr := httptest.NewRecorder()
	HTTPMiddleware(mux).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
	require.Equal(t, http.StatusCreated, rr.Code)

	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)
	found := false
	for _, span := range spans {
		if span.Name == "GET /x" {
			found = true
		}
	}
	require.True(t, found, "HTTP span with route not found: %+v", spans)
}

type traceWidget struct {
	ID   uint
	Name string
}

func TestGormPluginRecordsCreateSpan(t *testing.T) {
	exporter := installTestTracer(t)
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	InstrumentDB(db)
	require.NoError(t, db.AutoMigrate(&traceWidget{}))
	require.NoError(t, db.Create(&traceWidget{Name: "one"}).Error)

	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)
	found := false
	for _, span := range spans {
		if span.Name == "gorm.create" {
			found = true
		}
	}
	require.True(t, found, "GORM create span not found: %+v", spans)
}

func TestRedisHookRecordsCommandSpan(t *testing.T) {
	exporter := installTestTracer(t)
	ctx, err := (redisHook{}).BeforeProcess(context.Background(), redis.NewStringCmd(context.Background(), "get", "k"))
	require.NoError(t, err)
	require.NoError(t, (redisHook{}).AfterProcess(ctx, nil))

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	require.Equal(t, "redis get", spans[0].Name)
}
