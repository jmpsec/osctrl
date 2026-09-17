package logging

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
)

func TestCreateLoggerHTTPDefaults(t *testing.T) {
	l, err := CreateLoggerHTTP(&config.HTTPLogger{URL: "http://x"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if l.Configuration.Method != http.MethodPost {
		t.Errorf("method default: got %q want POST", l.Configuration.Method)
	}
	if l.Configuration.Format != HTTPFormatJSON {
		t.Errorf("format default: got %q want json", l.Configuration.Format)
	}
	if l.headers["Content-Type"] != "application/json" {
		t.Errorf("content-type default: got %q", l.headers["Content-Type"])
	}
	if !l.IsEnabled() || l.Name() != config.LoggingHTTP {
		t.Errorf("exporter name/enabled: %q %v", l.Name(), l.IsEnabled())
	}
}

func TestCreateLoggerHTTPNilConfigDoesNotPanic(t *testing.T) {
	l, err := CreateLoggerHTTP(nil)
	if err != nil {
		t.Fatalf("create nil: %v", err)
	}
	// Enabled defaults to true; Send is a no-op when URL is empty.
	l.Send("status", []byte(`{}`), "env", "uuid", false)
}

func TestLoggerHTTPSendJSON(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, err := CreateLoggerHTTP(&config.HTTPLogger{
		URL:    srv.URL,
		Method: "POST",
		Format: HTTPFormatJSON,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payload := []byte(`[{"name":"a"},{"name":"b"}]`)
	l.Send("result", payload, "prod", "node-1", false)

	if string(gotBody) != string(payload) {
		t.Errorf("json body: got %q want %q", gotBody, payload)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type: got %q want application/json", gotCT)
	}
}

func TestLoggerHTTPSendNDJSON(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{
		URL:    srv.URL,
		Format: HTTPFormatNDJSON,
	})
	l.Send("result", []byte(`[{"a":1},{"b":2}]`), "env", "uuid", false)

	lines := splitLines(string(gotBody))
	if len(lines) != 2 {
		t.Fatalf("ndjson lines: got %d want 2", len(lines))
	}
	if lines[0] != `{"a":1}` || lines[1] != `{"b":2}` {
		t.Errorf("ndjson body: got %q", gotBody)
	}
}

func TestLoggerHTTPSendMetadataEnvelope(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{
		URL:             srv.URL,
		IncludeMetadata: true,
	})
	l.Send("status", []byte(`[{"msg":"hi"}]`), "prod", "node-1", false)

	var envelopes []httpEnvelope
	if err := json.Unmarshal(gotBody, &envelopes); err != nil {
		t.Fatalf("unmarshal envelopes: %v (body=%q)", err, gotBody)
	}
	if len(envelopes) != 1 {
		t.Fatalf("envelope count: got %d want 1", len(envelopes))
	}
	if envelopes[0].Environment != "prod" || envelopes[0].UUID != "node-1" || envelopes[0].LogType != "status" {
		t.Errorf("envelope metadata: %+v", envelopes[0])
	}
	if string(envelopes[0].Event) != `{"msg":"hi"}` {
		t.Errorf("envelope event: got %q", envelopes[0].Event)
	}
}

func TestLoggerHTTPSendMetadataNDJSON(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{
		URL:             srv.URL,
		Format:          HTTPFormatNDJSON,
		IncludeMetadata: true,
	})
	l.Send("result", []byte(`[{"x":1},{"y":2}]`), "env", "node", false)

	lines := splitLines(string(gotBody))
	if len(lines) != 2 {
		t.Fatalf("ndjson envelope lines: got %d want 2", len(lines))
	}
	var first httpEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first line: %v", err)
	}
	if first.LogType != "result" {
		t.Errorf("first envelope logType: got %q want result", first.LogType)
	}
}

func TestLoggerHTTPSendRaw(t *testing.T) {
	var gotBody []byte
	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{
		URL:         srv.URL,
		Format:      HTTPFormatRaw,
		ContentType: "text/plain",
	})
	payload := []byte(`raw bytes here`)
	l.Send("status", payload, "env", "uuid", false)

	if string(gotBody) != string(payload) {
		t.Errorf("raw body: got %q want %q", gotBody, payload)
	}
	if gotCT != "text/plain" {
		t.Errorf("raw content-type: got %q want text/plain", gotCT)
	}
}

func TestLoggerHTTPCustomHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer xyz"},
	})
	l.Send("status", []byte(`{}`), "env", "uuid", false)

	if gotAuth != "Bearer xyz" {
		t.Errorf("custom header: got %q want Bearer xyz", gotAuth)
	}
}

func TestLoggerHTTPExportAdapter(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{URL: srv.URL})
	err := l.Export(types.QueryLog, []byte(`{"q":"test"}`), ExportParams{
		Environment: "env",
		UUID:        "node",
		QueryName:   "q1",
		Status:      0,
		Debug:       false,
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if string(gotBody) != `{"q":"test"}` {
		t.Errorf("export body: got %q", gotBody)
	}
}

func TestLoggerHTTPCloseIsIdempotent(t *testing.T) {
	l, _ := CreateLoggerHTTP(&config.HTTPLogger{URL: "http://x"})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close again: %v", err)
	}
}

func TestLoggerHTTPNon2xxDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{URL: srv.URL})
	l.Send("status", []byte(`{}`), "env", "uuid", false)
}

func TestLoggerHTTPMethodPUT(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := CreateLoggerHTTP(&config.HTTPLogger{URL: srv.URL, Method: "PUT"})
	l.Send("status", []byte(`{}`), "env", "uuid", false)

	if gotMethod != http.MethodPut {
		t.Errorf("method: got %q want PUT", gotMethod)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
