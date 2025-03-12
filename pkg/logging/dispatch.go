package logging

import (
	"encoding/json"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// DispatchLogs - Helper to dispatch logs
func (l *LoggerTLS) DispatchLogs(data []byte, uuid, logType, environment string, metadata nodes.NodeMetadata, debug bool) {
	// Use metadata to update record
	if err := l.Nodes.UpdateMetadataByUUID(uuid, metadata); err != nil {
		log.Err(err).Msg("error updating metadata")
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if debug {
		log.Debug().Msgf("dispatching logs to %s", l.Logging)
	}
	l.Log(logType, data, environment, uuid, debug)
}

// DispatchQueries - Helper to dispatch queries
func (l *LoggerTLS) DispatchQueries(queryData types.QueryWriteData, node nodes.OsqueryNode, debug bool) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Err(err).Msg("error preparing data")
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if debug {
		log.Debug().Msgf("dispatching queries to %s", l.Logging)
	}
	l.QueryLog(
		types.QueryLog,
		data,
		node.Environment,
		node.UUID,
		queryData.Name,
		queryData.Status,
		debug)
}
