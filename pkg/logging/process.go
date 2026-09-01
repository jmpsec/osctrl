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
// envID selects the environment-scoped exporter set.
func (l *LoggerTLS) ProcessLogs(data json.RawMessage, logType string, envID uint, environment, ipaddress string, dataLen int, debug bool) []types.LogResultData {
	// Parse log to extract metadata
	var logs []types.LogGenericData
	var resultLogs []types.LogResultData
	var statusLogs []types.LogStatusData
	var err error
	switch logType {
	case types.ResultLog:
		resultLogs, err = parseResultLogs(data)
		logs = make([]types.LogGenericData, len(resultLogs))
		for i, result := range resultLogs {
			logs[i] = types.LogGenericData{
				HostIdentifier: result.HostIdentifier,
				Decorations:    result.Decorations,
			}
		}
	case types.StatusLog:
		// When the alert matcher is attached, decode the full schema
		// once and derive the generic metadata view from it (the
		// matcher consumes the same slice — no second unmarshal).
		// Feature-off keeps the historical cheap generic-only decode.
		if l.Alerts != nil {
			statusLogs, err = decodeStatusLogs(data)
			logs = make([]types.LogGenericData, len(statusLogs))
			for i, status := range statusLogs {
				logs[i] = types.LogGenericData{
					HostIdentifier: status.HostIdentifier,
					Decorations:    status.Decorations,
				}
			}
		} else {
			err = json.Unmarshal(data, &logs)
		}
	default:
		err = json.Unmarshal(data, &logs)
	}
	if err != nil {
		// FIXME metrics for this
		log.Err(err).Msgf("error parsing log %s", string(data))
	}
	if debug {
		log.Debug().Msgf("parsing logs for metadata in %s:%s", logType, environment)
	}
	// Alert evaluation. The batches were decoded above; matching is a
	// pure snapshot read. The nil-check keeps the feature-off cost at a
	// single comparison.
	if l.Alerts != nil {
		switch logType {
		case types.ResultLog:
			l.Alerts.MatchResultLogs(envID, environment, resultLogs)
		case types.StatusLog:
			l.Alerts.MatchStatusLogs(envID, environment, statusLogs)
		}
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
	l.DispatchLogs(data, uuid, logType, envID, environment, metadata, debug)
	return resultLogs
}

// decodeStatusLogs decodes a status-log batch with the full schema.
// Called once per ProcessLogs invocation; the decoded slice feeds both
// the generic metadata extraction and the alert matcher. Malformed
// payloads yield nil — downstream consumers no-op on them.
func decodeStatusLogs(data json.RawMessage) ([]types.LogStatusData, error) {
	var statusLogs []types.LogStatusData
	if err := json.Unmarshal(data, &statusLogs); err != nil {
		return nil, err
	}
	return statusLogs, nil
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
	// Tap into results/statuses so we can update internal metrics. Failed
	// osquery queries may report only status/message without a result payload.
	queryNames := make(map[string]struct{}, len(queriesWrite.Queries)+len(queriesWrite.Statuses))
	for q := range queriesWrite.Queries {
		queryNames[q] = struct{}{}
	}
	for q := range queriesWrite.Statuses {
		queryNames[q] = struct{}{}
	}
	for q := range queryNames {
		status := queriesWrite.Statuses[q]
		if r, ok := queriesWrite.Queries[q]; ok {
			// Alert evaluation for distributed query results. Nil
			// matcher (feature off) costs one comparison.
			if l.Alerts != nil {
				l.Alerts.MatchQueryResult(envid, node.Environment, q, r, status, queriesWrite.Messages[q])
			}
			// Dispatch query name, result and status
			d := types.QueryWriteData{
				Name:    q,
				Result:  r,
				Status:  status,
				Message: queriesWrite.Messages[q],
			}
			go l.DispatchQueries(d, node, debug)
		}
		// TODO: need be refactored
		// Update internal metrics per query
		var err error
		if status != 0 {
			err = l.Queries.IncError(q, envid)
		} else {
			err = l.Queries.IncExecution(q, envid)
		}
		if err != nil {
			log.Err(err).Msg("error updating query")
		}
		// Update query status
		if err := l.Queries.UpdateQueryStatus(q, node.ID, status); err != nil {
			log.Err(err).Msg("error updating query status")
		}
	}
}
