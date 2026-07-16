package logging

import (
	"encoding/json"

	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

func parseResultLogs(data json.RawMessage) ([]types.LogResultData, error) {
	var logs []types.LogResultData
	if err := json.Unmarshal(data, &logs); err != nil {
		return nil, err
	}
	for i := range logs {
		if len(logs[i].Columns) == 0 && len(logs[i].Snapshot) > 0 {
			logs[i].Columns = logs[i].Snapshot
		}
	}
	return logs, nil
}

// ProcessLogs processes and dispatches logs. Result entries are returned so
// callers can reuse the decoded batch for secondary consumers such as posture.
func (l *LoggerTLS) ProcessLogs(data json.RawMessage, logType, environment, ipaddress string, dataLen int, debug bool) []types.LogResultData {
	// Parse log to extract metadata
	var logs []types.LogGenericData
	var resultLogs []types.LogResultData
	var err error
	if logType == types.ResultLog {
		resultLogs, err = parseResultLogs(data)
		logs = make([]types.LogGenericData, len(resultLogs))
		for i, result := range resultLogs {
			logs[i] = types.LogGenericData{
				HostIdentifier: result.HostIdentifier,
				Decorations:    result.Decorations,
			}
		}
	} else {
		err = json.Unmarshal(data, &logs)
	}
	if err != nil {
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
	return resultLogs
}

// ProcessLogQueryResult - Helper to process on-demand query result logs
func (l *LoggerTLS) ProcessLogQueryResult(queriesWrite types.QueryWriteRequest, envid uint, debug bool) {
	// Retrieve node
	node, err := l.Nodes.GetByKey(queriesWrite.NodeKey)
	if err != nil {
		log.Err(err).Msg("error retrieving node")
		return
	}
	// Integrity check — hard reject on env mismatch
	if envid != node.EnvironmentID {
		log.Error().Msgf("ProcessLogQueryResult: EnvID[%d] does not match Node.EnvironmentID[%d] — dropping results", envid, node.EnvironmentID)
		return
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
