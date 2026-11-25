package tracing

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
)

type gormPlugin struct{}

func (gormPlugin) Name() string { return "osctrl-tracing" }

// InstrumentDB enables GORM query spans when tracing is on.
func InstrumentDB(db *gorm.DB) {
	if db == nil || !Enabled() {
		return
	}
	_ = db.Use(gormPlugin{})
}

func (gormPlugin) Initialize(db *gorm.DB) error {
	type registration struct {
		register func(string, func(*gorm.DB)) error
		name     string
		fn       func(*gorm.DB)
	}
	registrations := []registration{
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Create().Before("gorm:create").Register(n, f)
		}, "osctrl:tracing:create:before", gormBefore("create")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Create().After("gorm:create").Register(n, f)
		}, "osctrl:tracing:create:after", gormAfter("create")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Query().Before("gorm:query").Register(n, f)
		}, "osctrl:tracing:query:before", gormBefore("query")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Query().After("gorm:query").Register(n, f)
		}, "osctrl:tracing:query:after", gormAfter("query")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Update().Before("gorm:update").Register(n, f)
		}, "osctrl:tracing:update:before", gormBefore("update")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Update().After("gorm:update").Register(n, f)
		}, "osctrl:tracing:update:after", gormAfter("update")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Delete().Before("gorm:delete").Register(n, f)
		}, "osctrl:tracing:delete:before", gormBefore("delete")},
		{func(n string, f func(*gorm.DB)) error {
			return db.Callback().Delete().After("gorm:delete").Register(n, f)
		}, "osctrl:tracing:delete:after", gormAfter("delete")},
		{func(n string, f func(*gorm.DB)) error { return db.Callback().Row().Before("gorm:row").Register(n, f) }, "osctrl:tracing:row:before", gormBefore("row")},
		{func(n string, f func(*gorm.DB)) error { return db.Callback().Row().After("gorm:row").Register(n, f) }, "osctrl:tracing:row:after", gormAfter("row")},
		{func(n string, f func(*gorm.DB)) error { return db.Callback().Raw().Before("gorm:raw").Register(n, f) }, "osctrl:tracing:raw:before", gormBefore("raw")},
		{func(n string, f func(*gorm.DB)) error { return db.Callback().Raw().After("gorm:raw").Register(n, f) }, "osctrl:tracing:raw:after", gormAfter("raw")},
	}
	for _, reg := range registrations {
		if err := reg.register(reg.name, reg.fn); err != nil {
			return err
		}
	}
	return nil
}

func gormBefore(op string) func(*gorm.DB) {
	return func(db *gorm.DB) {
		if db.Statement == nil {
			return
		}
		ctx := db.Statement.Context
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, span := Tracer().Start(ctx, "gorm."+op, trace.WithSpanKind(trace.SpanKindClient))
		attrs := []attribute.KeyValue{
			attribute.String("db.system", db.Name()),
			attribute.String("db.operation", op),
		}
		if db.Statement.Table != "" {
			attrs = append(attrs, attribute.String("db.sql.table", db.Statement.Table))
		}
		span.SetAttributes(attrs...)
		db.Statement.Context = ctx
		db.InstanceSet("osctrl:tracing:span:"+op, span)
	}
}

func gormAfter(op string) func(*gorm.DB) {
	return func(db *gorm.DB) {
		ctx := context.Background()
		if db.Statement != nil && db.Statement.Context != nil {
			ctx = db.Statement.Context
		}
		span := trace.SpanFromContext(ctx)
		if value, ok := db.InstanceGet("osctrl:tracing:span:" + op); ok {
			if stored, ok := value.(trace.Span); ok {
				span = stored
			}
		}
		if !span.SpanContext().IsValid() {
			return
		}
		if op == "create" || op == "update" || op == "delete" {
			span.SetAttributes(attribute.Int64("db.rows_affected", db.RowsAffected))
		}
		span.End()
	}
}
