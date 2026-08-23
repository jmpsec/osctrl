package logging

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

func TestProcessLogQueryResultUpdatesStatusOnlyError(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	nodeMgr := nodes.CreateNodes(db)
	queryMgr := queries.CreateQueries(db)
	logger := &LoggerTLS{
		Logging:   config.LoggingNone,
		exporters: map[uint]*MultiExporter{0: NewMultiExporter(&LoggerNone{Enabled: false})},
		Nodes:     nodeMgr,
		Queries:   queryMgr,
	}
	node := nodes.OsqueryNode{NodeKey: "node-key", UUID: "NODE-A", EnvironmentID: 1, Environment: "env"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	query := queries.DistributedQuery{Name: "console-query", Query: "select * from missing_table", Active: true, EnvironmentID: 1, Type: queries.ConsoleQueryType}
	if err := queryMgr.Create(&query); err != nil {
		t.Fatalf("create query: %v", err)
	}
	if err := queryMgr.CreateNodeQueries([]uint{node.ID}, query.ID); err != nil {
		t.Fatalf("create node query: %v", err)
	}

	logger.ProcessLogQueryResult(types.QueryWriteRequest{
		NodeKey:  "node-key",
		Queries:  types.QueryWriteQueries{},
		Statuses: types.QueryWriteStatuses{"console-query": 1},
		Messages: types.QueryWriteMessages{"console-query": "no such table: missing_table"},
	}, 1, false)

	var nodeQuery queries.NodeQuery
	if err := db.Where("node_id = ? AND query_id = ?", node.ID, query.ID).First(&nodeQuery).Error; err != nil {
		t.Fatalf("find node query: %v", err)
	}
	if nodeQuery.Status != queries.DistributedQueryStatusError {
		t.Fatalf("expected status-only query write to mark node query error, got %q", nodeQuery.Status)
	}
}

func TestGetNodeLogsSeverityFilter(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&OsqueryStatusData{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	rows := []OsqueryStatusData{
		{UUID: "NODE-UUID", Environment: "env", Message: "info msg", Severity: "0"},
		{UUID: "NODE-UUID", Environment: "env", Message: "warn msg", Severity: "1"},
		{UUID: "NODE-UUID", Environment: "env", Message: "error msg", Severity: "2"},
	}
	for _, r := range rows {
		if err := db.Create(&r).Error; err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	// No severity filter — all 3 rows
	all, err := GetNodeLogs(db, types.StatusLog, "env", "node-uuid", time.Time{}, 100, "", "")
	if err != nil {
		t.Fatalf("GetNodeLogs: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 rows without filter, got %d", len(all))
	}

	// Filter by severity=2 (error) — only 1 row
	errOnly, err := GetNodeLogs(db, types.StatusLog, "env", "node-uuid", time.Time{}, 100, "", "2")
	if err != nil {
		t.Fatalf("GetNodeLogs: %v", err)
	}
	if len(errOnly) != 1 {
		t.Fatalf("expected 1 error row, got %d", len(errOnly))
	}
	if errOnly[0]["severity"] != "2" {
		t.Fatalf("expected severity 2, got %v", errOnly[0]["severity"])
	}

	// Filter by severity=1 (warning) — only 1 row
	warnOnly, err := GetNodeLogs(db, types.StatusLog, "env", "node-uuid", time.Time{}, 100, "", "1")
	if err != nil {
		t.Fatalf("GetNodeLogs: %v", err)
	}
	if len(warnOnly) != 1 {
		t.Fatalf("expected 1 warning row, got %d", len(warnOnly))
	}

	// Filter by severity=0 (info) — only 1 row
	infoOnly, err := GetNodeLogs(db, types.StatusLog, "env", "node-uuid", time.Time{}, 100, "", "0")
	if err != nil {
		t.Fatalf("GetNodeLogs: %v", err)
	}
	if len(infoOnly) != 1 {
		t.Fatalf("expected 1 info row, got %d", len(infoOnly))
	}
}
