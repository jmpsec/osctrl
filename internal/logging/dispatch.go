package logging

import (
	"encoding/json"
	"osctrl/internal/nodes"
	"osctrl/internal/types"

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
	// Refresh last logging request
	if logType == types.StatusLog {
		// Update metadata for node
		if err := l.Nodes.RefreshLastStatus(uuid); err != nil {
			log.Err(err).Msg("error refreshing last status")
		}
	}
	if logType == types.ResultLog {
		// Update metadata for node
		if err := l.Nodes.RefreshLastResult(uuid); err != nil {
			log.Err(err).Msg("error refreshing last result")
		}
	}
}

// DispatchQueries - Helper to dispatch queries
func (l *LoggerTLS) DispatchQueries(queryData types.QueryWriteData, node nodes.OsqueryNode, debug bool) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Err(err).Msg("error preparing data")
	}
	// Refresh last query write request
	if err := l.Nodes.RefreshLastQueryWrite(node.UUID); err != nil {
		log.Err(err).Msg("error refreshing last query write")
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
