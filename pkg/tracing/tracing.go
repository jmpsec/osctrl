// Package tracing initializes optional OpenTelemetry tracing for osctrl and
// provides HTTP, GORM, and Redis instrumentation helpers. Tracing is disabled
// unless explicitly enabled; the helpers are no-ops in that case.
package tracing

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var enabled atomic.Bool

// Config controls the process-wide tracer provider.
type Config struct {
	Enabled        bool
	Endpoint       string
	Insecure       bool
	SampleRatio    float64
	ServiceName    string
	ServiceVersion string
	Environment    string
}

// Setup initializes the OTLP HTTP exporter and tracer provider. It returns a
// shutdown function even when tracing is disabled.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, nil
	}
	if cfg.SampleRatio < 0 || cfg.SampleRatio > 1 {
		return nil, fmt.Errorf("tracing sample ratio must be between 0 and 1")
	}

	opts := []otlptracehttp.Option{}
	if endpoint := strings.TrimSpace(cfg.Endpoint); endpoint != "" {
		if strings.Contains(endpoint, "://") {
			// A full URL carries its scheme and path, so let the exporter
			// derive both instead of forcing host:port semantics.
			opts = append(opts, otlptracehttp.WithEndpointURL(endpoint))
		} else {
			opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
			if cfg.Insecure {
				opts = append(opts, otlptracehttp.WithInsecure())
			}
		}
	} else if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	attrs := []attribute.KeyValue{
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.ServiceVersion),
	}
	if cfg.Environment != "" {
		attrs = append(attrs, attribute.String("deployment.environment", cfg.Environment))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, fmt.Errorf("create tracing resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	enabled.Store(true)
	return provider.Shutdown, nil
}

// Enabled reports whether tracing was successfully enabled.
func Enabled() bool { return enabled.Load() }

// Tracer returns the shared osctrl tracer.
func Tracer() trace.Tracer { return otel.Tracer("github.com/jmpsec/osctrl") }

// StartSpan is a convenience wrapper for background workers.
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name)
}
