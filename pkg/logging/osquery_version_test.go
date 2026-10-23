package logging

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// A default environment has an empty schedule, so a node may send only status
// logs, which can carry no decorations. Their top-level "version" is then the
// only way the node row learns its osquery version, which upgrade
// confirmation compares against.
func TestProcessLogsOsqueryVersionFallback(t *testing.T) {
	tests := []struct {
		name    string
		logType string
		batch   string
		want    string
	}{
		{"status version without decorations", types.StatusLog,
			`[{"hostIdentifier":"N","severity":"0","message":"m","version":"5.13.0"}]`, "5.13.0"},
		{"most recent valid status version", types.StatusLog,
			`[{"message":"a","version":"5.12.1"},{"message":"b","version":"5.13.0"},{"message":"c","version":""}]`, "5.13.0"},
		{"decoration wins", types.StatusLog,
			`[{"message":"m","version":"5.13.0","decorations":{"osquery_version":"5.14.1"}}]`, "5.14.1"},
		{"injection ignored", types.StatusLog,
			`[{"message":"m","version":"5.13.0; drop"}]`, "5.0.0"},
		{"empty ignored", types.StatusLog,
			`[{"message":"m","version":""}]`, "5.0.0"},
		{"oversized parts ignored", types.StatusLog,
			`[{"message":"m","version":"5.1234567.0"}]`, "5.0.0"},
		{"over-long ignored", types.StatusLog,
			`[{"message":"m","version":"` + strings.Repeat("1.", 40) + `1"}]`, "5.0.0"},
		{"result logs unaffected", types.ResultLog,
			`[{"name":"q","hostIdentifier":"N","columns":{"a":"b"},"version":"5.13.0"}]`, "5.0.0"},
	}
	for _, tc := range tests {
		for _, alerts := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/no-alerts", true: "/alerts"}[alerts], func(t *testing.T) {
				dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
				db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
				require.NoError(t, err)
				nodeMgr := nodes.CreateNodes(db)
				node := nodes.OsqueryNode{UUID: "N", NodeKey: "k", EnvironmentID: 1, Environment: "prod", OsqueryVersion: "5.0.0"}
				require.NoError(t, db.Create(&node).Error)
				logger := &LoggerTLS{
					Logging:   config.LoggingNone,
					exporters: map[uint]*MultiExporter{0: NewMultiExporter(&LoggerNone{Enabled: false})},
					Nodes:     nodeMgr,
				}
				if alerts {
					logger.Alerts = &recordingMatcher{}
				}
				data := json.RawMessage(tc.batch)
				logger.ProcessLogs(node, data, tc.logType, 1, "prod", "10.0.0.1", len(data), false)
				var got nodes.OsqueryNode
				require.NoError(t, db.First(&got, node.ID).Error)
				require.Equal(t, tc.want, got.OsqueryVersion)
			})
		}
	}
}
