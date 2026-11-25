package tracing

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// HTTPMiddleware starts a server span for each request, extracts the incoming
// W3C trace context, and records method, route, status and duration. It
// preserves Flusher, Hijacker, Pusher and ReaderFrom for SSE and downloads.
func HTTPMiddleware(next http.Handler) http.Handler {
	if !Enabled() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := Tracer().Start(ctx, "HTTP "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()

		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.scheme", "https"),
			attribute.String("server.address", r.Host),
			attribute.String("user_agent.original", r.UserAgent()),
		)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		req := r.WithContext(ctx)
		next.ServeHTTP(recorder, req)

		route := req.Pattern
		if route == "" {
			route = "unmatched"
		}
		if strings.HasPrefix(route, r.Method+" ") {
			span.SetName(route)
		} else {
			span.SetName(r.Method + " " + route)
		}
		span.SetAttributes(
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", recorder.status),
		)
		if recorder.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, http.StatusText(recorder.status))
		}
	})
}

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
		return nil, nil, fmt.Errorf("tracing: ResponseWriter does not implement http.Hijacker")
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
