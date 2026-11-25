package tracing

import (
	"context"

	"github.com/go-redis/redis/v8"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type redisHook struct{}

// InstrumentRedis attaches a tracing hook to every Redis command and
// pipeline. It is a no-op when tracing is disabled.
func InstrumentRedis(client *redis.Client) {
	if client == nil || !Enabled() {
		return
	}
	client.AddHook(redisHook{})
}

func (redisHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	ctx, span := Tracer().Start(ctx, "redis "+cmd.Name(), trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", cmd.Name()),
	)
	return ctx, nil
}

func (redisHook) AfterProcess(ctx context.Context, _ redis.Cmder) error {
	trace.SpanFromContext(ctx).End()
	return nil
}

func (redisHook) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	ctx, span := Tracer().Start(ctx, "redis pipeline", trace.WithSpanKind(trace.SpanKindClient))
	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.Int("db.redis.pipeline_length", len(cmds)),
	)
	return ctx, nil
}

func (redisHook) AfterProcessPipeline(ctx context.Context, _ []redis.Cmder) error {
	trace.SpanFromContext(ctx).End()
	return nil
}
