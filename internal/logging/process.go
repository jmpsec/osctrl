package logging

import (
	"encoding/json"
	"osctrl/internal/nodes"
	"osctrl/internal/types"

	"github.com/rs/zerolog/log"
)

// ProcessLogs - Helper to process logs
func (l *LoggerTLS) ProcessLogs(data json.RawMessage, logType, environment, ipaddress string, dataLen int, debug bool) {
	// Parse log to extract metadata
	var logs []types.LogGenericData
	if err := json.Unmarshal(data, &logs); err != nil {
		// FIXME metrics for this
		log.Err(err).Msgf("error parsing log %s", string(data))
	}
	if debug {
		log.Debug().Msgf("parsing logs for metadata in %s:%s", logType, environment)
	}
	// Iterate through received messages to extract metadata
	var uuid, hostname, localname, username, osqueryuser, confighash, daemonhash, osqueryversion string
	for _, l := range logs {
		uuid = metadataVerification(uuid, l.HostIdentifier)
		hostname = metadataVerification(hostname, l.Decorations.Hostname)
		localname = metadataVerification(localname, l.Decorations.LocalHostname)
		username = metadataVerification(username, l.Decorations.Username)
		osqueryuser = metadataVerification(osqueryuser, l.Decorations.OsqueryUser)
		confighash = metadataVerification(confighash, l.Decorations.ConfigHash)
		daemonhash = metadataVerification(daemonhash, l.Decorations.DaemonHash)
		osqueryversion = metadataVerification(osqueryversion, l.Decorations.OsqueryVersion)
	}
	if debug {
		log.Debug().Msgf("metadata and dispatch for %s", uuid)
	}
	metadata := nodes.NodeMetadata{
		IPAddress:      ipaddress,
		Username:       username,
		OsqueryUser:    osqueryuser,
		Hostname:       hostname,
		Localname:      localname,
		ConfigHash:     confighash,
		DaemonHash:     daemonhash,
		OsqueryVersion: osqueryversion,
		BytesReceived:  dataLen,
	}
	// Dispatch logs and update metadata
	l.DispatchLogs(data, uuid, logType, environment, metadata, debug)
}

// ProcessLogQueryResult - Helper to process on-demand query result logs
func (l *LoggerTLS) ProcessLogQueryResult(queriesWrite types.QueryWriteRequest, envid uint, debug bool) {
	// Retrieve node
	node, err := l.Nodes.GetByKey(queriesWrite.NodeKey)
	if err != nil {
		log.Err(err).Msg("error retrieving node")
	}
	// Integrity check
	if envid != node.EnvironmentID {
		log.Error().Msgf("ProcessLogQueryResult: EnvID[%d] does not match Node.EnvironmentID[%d]", envid, node.EnvironmentID)
	}
	// Tap into results so we can update internal metrics
	for q, r := range queriesWrite.Queries {
		// Dispatch query name, result and status
		d := types.QueryWriteData{
			Name:    q,
			Result:  r,
			Status:  queriesWrite.Statuses[q],
			Message: queriesWrite.Messages[q],
		}
		go l.DispatchQueries(d, node, debug)
		// TODO: need be refactored
		// Update internal metrics per query
		var err error
		if queriesWrite.Statuses[q] != 0 {
			err = l.Queries.IncError(q, envid)
		} else {
			err = l.Queries.IncExecution(q, envid)
		}
		if err != nil {
			log.Err(err).Msg("error updating query")
		}
		// Update query status
		if err := l.Queries.UpdateQueryStatus(q, node.ID, queriesWrite.Statuses[q]); err != nil {
			log.Err(err).Msg("error updating query status")
		}
	}
}
