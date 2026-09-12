package logging

import (
	"encoding/json"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// DispatchLogs - Helper to dispatch logs. envID selects the exporter
// set for this environment (with global fallback handled inside
// LoggerTLS.LogWithEnv). The string environment is forwarded as
// metadata for exporters that embed it (Splunk source type, DB row,
// etc.).
func (l *LoggerTLS) DispatchLogs(data []byte, uuid, logType string, envID uint, environment string, metadata nodes.NodeMetadata, debug bool) {
	// Use metadata to update record
	if err := l.Nodes.UpdateMetadataByUUID(uuid, metadata); err != nil {
		log.Err(err).Msg("error updating metadata")
	}
	if debug {
		log.Debug().Msgf("dispatching logs to %s", l.Logging)
	}
	l.LogWithEnv(logType, data, envID, environment, uuid, debug)
}

// DispatchQueries - Helper to dispatch queries. Uses the node's
// EnvironmentID to select the env-scoped exporter set.
func (l *LoggerTLS) DispatchQueries(queryData types.QueryWriteData, node nodes.OsqueryNode, debug bool) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Err(err).Msg("error preparing data")
	}
	if debug {
		log.Debug().Msgf("dispatching queries to %s", l.Logging)
	}
	l.QueryLogWithEnv(
		types.QueryLog,
		data,
		node.EnvironmentID,
		node.Environment,
		node.UUID,
		queryData.Name,
		queryData.Status,
		debug)
	// Export completion is only an invalidation hint. Some sinks do not
	// acknowledge persistence, so clients must retain result reconciliation.
	if l.Queries != nil {
		l.Queries.NotifyResults(queryData.Name, node.EnvironmentID)
	}
}
