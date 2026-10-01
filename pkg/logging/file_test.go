package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/types"
)

// TestLoggerFileWritesStatusResultQuery is a regression test for
// https://github.com/jmpsec/osctrl/issues/1068 — the file sink built
// zerolog events without ever terminating them, so nothing was written
// and the target file was not even created.
func TestLoggerFileWritesStatusResultQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.log")
	lf, err := CreateLoggerFile(&config.LocalLogger{FilePath: path, MaxSize: 1})
	if err != nil {
		t.Fatalf("create file logger: %v", err)
	}
	data := []byte(`[{"name":"q","hostIdentifier":"h"}]`)
	lf.Log(types.StatusLog, data, "env", "uuid-1", false)
	lf.Log(types.ResultLog, data, "env", "uuid-1", false)
	if err := lf.Export(types.QueryLog, data, ExportParams{Environment: "env", UUID: "uuid-1", QueryName: "q"}); err != nil {
		t.Fatalf("export query log: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file sink wrote nothing: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines written: got %d want 3", len(lines))
	}
	wantTypes := []string{types.StatusLog, types.ResultLog, types.QueryLog}
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i+1, err)
		}
		if got := entry["type"]; got != wantTypes[i] {
			t.Errorf("line %d type: got %v want %q", i+1, got, wantTypes[i])
		}
		if got := entry["environment"]; got != "env" {
			t.Errorf("line %d environment: got %v want env", i+1, got)
		}
		if got := entry["uuid"]; got != "uuid-1" {
			t.Errorf("line %d uuid: got %v want uuid-1", i+1, got)
		}
		// zerolog RawJSON inlines the payload as a raw JSON value.
		var want any
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		var gotData any
		if entry["data"] == nil {
			t.Errorf("line %d missing data field", i+1)
		} else {
			raw, err := json.Marshal(entry["data"])
			if err != nil {
				t.Fatalf("line %d marshal data: %v", i+1, err)
			}
			if err := json.Unmarshal(raw, &gotData); err != nil {
				t.Fatalf("line %d unmarshal data: %v", i+1, err)
			}
		}
		if !reflect.DeepEqual(gotData, want) {
			t.Errorf("line %d data: got %v want %s", i+1, entry["data"], data)
		}
	}
}
