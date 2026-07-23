package logging

import (
	"encoding/json"
	"testing"

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
		Logging: config.LoggingNone,
		Logger:  &LoggerNone{Enabled: false},
		Nodes:   nodeMgr,
		Queries: queryMgr,
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
