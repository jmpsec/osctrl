package logging

import (
	"encoding/json"
	"log"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/types"
)

// DispatchLogs - Helper to dispatch logs
func (l *LoggerTLS) DispatchLogs(data []byte, uuid, logType, environment string, metadata nodes.NodeMetadata, debug bool) {
	// Use metadata to update record
	if err := l.Nodes.UpdateMetadataByUUID(uuid, metadata); err != nil {
		log.Printf("error updating metadata %s", err)
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if debug {
		log.Printf("dispatching logs to %s", l.Logging)
	}
	l.Log(logType, data, environment, uuid, debug)
	// Refresh last logging request
	if logType == types.StatusLog {
		if err := l.Nodes.RefreshLastStatus(uuid); err != nil {
			log.Printf("error refreshing last status %v", err)
		}
	}
	if logType == types.ResultLog {
		if err := l.Nodes.RefreshLastResult(uuid); err != nil {
			log.Printf("error refreshing last result %v", err)
		}
	}
}

// DispatchQueries - Helper to dispatch queries
func (l *LoggerTLS) DispatchQueries(queryData types.QueryWriteData, node nodes.OsqueryNode, debug bool) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Printf("error preparing data %v", err)
	}
	// Refresh last query write request
	if err := l.Nodes.RefreshLastQueryWrite(node.UUID); err != nil {
		log.Printf("error refreshing last query write %v", err)
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if debug {
		log.Printf("dispatching queries to %s", l.Logging)
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
