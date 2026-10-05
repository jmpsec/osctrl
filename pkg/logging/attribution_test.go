package logging

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
)

// A log batch is authenticated by node_key as one node, but every entry in it
// carries a hostIdentifier the sender writes. Nothing the batch produces — the
// metadata update, the stored rows, alert hits — may follow that claim, or any
// enrolled node could overwrite another's metadata, plant log lines on its
// page, and frame it in alerts.
func TestProcessLogsAttributesToAuthenticatedNode(t *testing.T) {
	logDB := newTestLoggerDB(t)
	db := logDB.Database.Conn
	attacker := nodes.OsqueryNode{UUID: "ATTACKER", EnvironmentID: 1, Environment: "prod", Hostname: "attacker-host"}
	victim := nodes.OsqueryNode{UUID: "VICTIM", EnvironmentID: 1, Environment: "prod", Hostname: "victim-host"}
	nodeMgr := nodes.CreateNodes(db)
	require.NoError(t, db.Create(&attacker).Error)
	require.NoError(t, db.Create(&victim).Error)

	matcher := &recordingMatcher{}
	logger := &LoggerTLS{Logging: "db", Nodes: nodeMgr, Queries: queries.CreateQueries(db), Alerts: matcher}
	logger.ReplaceExporters(map[uint]*MultiExporter{0: NewMultiExporter(logDB)})

	status := json.RawMessage(`[{"hostIdentifier":"VICTIM","severity":"2","message":"planted","decorations":{"hostname":"spoofed"}}]`)
	logger.ProcessLogs(attacker, status, types.StatusLog, 1, "prod", "10.0.0.9", len(status), false)
	require.Equal(t, "ATTACKER", matcher.lastNodeUUID, "status alerts must be attributed to the sender")

	result := json.RawMessage(`[{"name":"pack_x","hostIdentifier":"VICTIM","columns":{"a":"b"},"decorations":{"hostname":"spoofed"}}]`)
	logger.ProcessLogs(attacker, result, types.ResultLog, 1, "prod", "10.0.0.9", len(result), false)
	require.Equal(t, "ATTACKER", matcher.lastNodeUUID, "result alerts must be attributed to the sender")

	// The victim's row is untouched; the batch describes its sender.
	var gotVictim, gotAttacker nodes.OsqueryNode
	require.NoError(t, db.First(&gotVictim, victim.ID).Error)
	require.NoError(t, db.First(&gotAttacker, attacker.ID).Error)
	require.Equal(t, "victim-host", gotVictim.Hostname, "a claimed hostIdentifier overwrote another node's metadata")
	require.Zero(t, gotVictim.BytesReceived)
	require.Equal(t, "spoofed", gotAttacker.Hostname)
	require.Equal(t, len(status)+len(result), gotAttacker.BytesReceived)

	// Stored rows are filed under the sender, never the claimed node.
	for _, model := range []any{&OsqueryStatusData{}, &OsqueryResultData{}} {
		var claimed, sender int64
		require.NoError(t, db.Model(model).Where("uuid = ?", "VICTIM").Count(&claimed).Error)
		require.NoError(t, db.Model(model).Where("uuid = ?", "ATTACKER").Count(&sender).Error)
		require.Zerof(t, claimed, "%T rows filed under the claimed node", model)
		require.EqualValuesf(t, 1, sender, "%T rows not filed under the sender", model)
	}
}
