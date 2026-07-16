package logging

import (
	"encoding/json"
	"testing"
)

func TestParseResultLogsPreservesPostureColumns(t *testing.T) {
	data := json.RawMessage(`[{"name":"osctrl:posture:users","columns":[{"username":"alice"}],"hostIdentifier":"NODE-A","decorations":{"hostname":"host-a"}}]`)

	logs, err := parseResultLogs(data)
	if err != nil {
		t.Fatalf("parse result logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected one result, got %d", len(logs))
	}
	if logs[0].Name != "osctrl:posture:users" || string(logs[0].Columns) != `[{"username":"alice"}]` {
		t.Fatalf("result data was not preserved: %+v", logs[0])
	}
}

func TestParseResultLogsUsesSnapshotAsColumnsForSnapshotResults(t *testing.T) {
	data := json.RawMessage(`[{"name":"osctrl:posture:listening_ports","action":"snapshot","snapshot":[{"address":"127.0.0.11","port":"35279"}],"hostIdentifier":"NODE-A","decorations":{"hostname":"host-a"}}]`)

	logs, err := parseResultLogs(data)
	if err != nil {
		t.Fatalf("parse result logs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected one result, got %d", len(logs))
	}
	if string(logs[0].Columns) != `[{"address":"127.0.0.11","port":"35279"}]` {
		t.Fatalf("snapshot data was not normalized into columns: %+v", logs[0])
	}
}
