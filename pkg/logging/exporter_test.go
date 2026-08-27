package logging

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
)

type exportCall struct {
	logType string
	data    string
	params  ExportParams
}

type recordingExporter struct {
	name    string
	enabled bool
	err     error
	calls   []exportCall
}

func (r *recordingExporter) Name() string {
	return r.name
}

func (r *recordingExporter) IsEnabled() bool {
	return r.enabled
}

func (r *recordingExporter) Export(logType string, data []byte, params ExportParams) error {
	r.calls = append(r.calls, exportCall{
		logType: logType,
		data:    string(data),
		params:  params,
	})
	return r.err
}

func (r *recordingExporter) Close() error { return nil }

func TestMultiExporterFansOutAndContinuesAfterError(t *testing.T) {
	boom := errors.New("boom")
	first := &recordingExporter{name: "first", enabled: true}
	disabled := &recordingExporter{name: "disabled", enabled: false}
	failing := &recordingExporter{name: "failing", enabled: true, err: boom}
	last := &recordingExporter{name: "last", enabled: true}
	multi := NewMultiExporter(first, disabled, failing, last)

	params := ExportParams{
		Environment: "prod",
		UUID:        "NODE-A",
		QueryName:   "query-a",
		Status:      7,
		Debug:       true,
	}
	err := multi.Export(types.QueryLog, []byte(`{"ok":true}`), params)
	if err == nil {
		t.Fatalf("expected joined exporter error")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("expected joined error to include boom, got %v", err)
	}

	for _, exporter := range []*recordingExporter{first, failing, last} {
		if len(exporter.calls) != 1 {
			t.Fatalf("%s calls: got %d want 1", exporter.name, len(exporter.calls))
		}
		if exporter.calls[0].logType != types.QueryLog {
			t.Fatalf("%s log type: got %q want %q", exporter.name, exporter.calls[0].logType, types.QueryLog)
		}
		if exporter.calls[0].data != `{"ok":true}` {
			t.Fatalf("%s data: got %q", exporter.name, exporter.calls[0].data)
		}
		if !reflect.DeepEqual(exporter.calls[0].params, params) {
			t.Fatalf("%s params: got %+v want %+v", exporter.name, exporter.calls[0].params, params)
		}
	}
	if len(disabled.calls) != 0 {
		t.Fatalf("disabled exporter was called")
	}
}

func TestConfiguredExporterTypesPrefersMultiValue(t *testing.T) {
	got := configuredExporterTypes(&config.YAMLConfigurationLogger{
		Type:  config.LoggingDB,
		Types: []string{" stdout ", "STDOUT", "none"},
	})
	want := []string{config.LoggingStdout, config.LoggingNone}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configured exporter types: got %#v want %#v", got, want)
	}
}

func TestConfiguredExporterTypesFallsBackToLegacyType(t *testing.T) {
	got := configuredExporterTypes(&config.YAMLConfigurationLogger{Type: config.LoggingNone})
	want := []string{config.LoggingNone}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("configured exporter types: got %#v want %#v", got, want)
	}
}

func TestCreateExportersAddsAlwaysLogDBWhenPrimaryDBNotConfigured(t *testing.T) {
	dbPath := t.TempDir() + "/always-log.db"
	exporters, err := CreateExporters(config.ServiceParameters{
		DB: &config.YAMLConfigurationDB{
			Type:            "sqlite",
			FilePath:        dbPath,
			MaxIdleConns:    1,
			MaxOpenConns:    1,
			ConnMaxLifetime: 1,
		},
		Logger: &config.YAMLConfigurationLogger{
			Type:      config.LoggingNone,
			AlwaysLog: true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("create exporters: %v", err)
	}
	got := exporters.ExporterNames()
	want := []string{config.LoggingNone, config.LoggingDB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exporter names: got %#v want %#v", got, want)
	}
}

func TestCreateExportersDoesNotDuplicateAlwaysLogDB(t *testing.T) {
	dbPath := t.TempDir() + "/primary-db.db"
	exporters, err := CreateExporters(config.ServiceParameters{
		DB: &config.YAMLConfigurationDB{
			Type:            "sqlite",
			FilePath:        dbPath,
			MaxIdleConns:    1,
			MaxOpenConns:    1,
			ConnMaxLifetime: 1,
		},
		Logger: &config.YAMLConfigurationLogger{
			Type:         config.LoggingDB,
			LoggerDBSame: true,
			AlwaysLog:    true,
		},
	}, nil)
	if err != nil {
		t.Fatalf("create exporters: %v", err)
	}
	got := exporters.ExporterNames()
	want := []string{config.LoggingDB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exporter names: got %#v want %#v", got, want)
	}
}

func TestMultiExporterCategoryFiltering(t *testing.T) {
	statusOnly := &recordingExporter{name: "status-only", enabled: true}
	allSink := &recordingExporter{name: "all-sink", enabled: true}
	queryAndResult := &recordingExporter{name: "query-result", enabled: true}

	entries := []ExporterEntry{
		{SinkID: 1, Exporter: statusOnly, Categories: []string{"status"}},
		{SinkID: 2, Exporter: allSink, Categories: nil}, // nil = all
		{SinkID: 3, Exporter: queryAndResult, Categories: []string{"query", "result"}},
	}
	multi := NewMultiExporterWithStats(entries)
	params := ExportParams{Environment: "env", UUID: "node-1"}

	// Send a status log — statusOnly and allSink should receive it.
	_ = multi.Export("status", []byte(`{"msg":"info"}`), params)
	if len(statusOnly.calls) != 1 {
		t.Fatalf("status-only should receive status, got %d calls", len(statusOnly.calls))
	}
	if len(allSink.calls) != 1 {
		t.Fatalf("all-sink should receive status, got %d calls", len(allSink.calls))
	}
	if len(queryAndResult.calls) != 0 {
		t.Fatalf("query-result should NOT receive status, got %d calls", len(queryAndResult.calls))
	}

	// Send a query log — allSink and queryAndResult should receive it.
	_ = multi.Export("query", []byte(`{"msg":"result"}`), params)
	if len(statusOnly.calls) != 1 {
		t.Fatalf("status-only should NOT receive query, got %d calls", len(statusOnly.calls))
	}
	if len(allSink.calls) != 2 {
		t.Fatalf("all-sink should receive query, got %d calls", len(allSink.calls))
	}
	if len(queryAndResult.calls) != 1 {
		t.Fatalf("query-result should receive query, got %d calls", len(queryAndResult.calls))
	}

	// Send a carve.meta event — only allSink should receive it.
	_ = multi.Export("carve.meta", []byte(`{"event":"scheduled"}`), params)
	if len(statusOnly.calls) != 1 {
		t.Fatalf("status-only should NOT receive carve.meta, got %d calls", len(statusOnly.calls))
	}
	if len(allSink.calls) != 3 {
		t.Fatalf("all-sink should receive carve.meta, got %d calls", len(allSink.calls))
	}
	if len(queryAndResult.calls) != 1 {
		t.Fatalf("query-result should NOT receive carve.meta, got %d calls", len(queryAndResult.calls))
	}
}
