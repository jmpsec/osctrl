package logging

import (
	"encoding/json"
	"log"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/types"
)

// ProcessLogs - Helper to process logs
func (l *LoggerTLS) ProcessLogs(data json.RawMessage, logType, environment, ipaddress string, dataLen int, debug bool) {
	// Parse log to extract metadata
	var logs []types.LogGenericData
	if err := json.Unmarshal(data, &logs); err != nil {
		// FIXME metrics for this
		log.Printf("error parsing log %s %v", string(data), err)
	}
	if debug {
		log.Printf("parsing logs for metadata in %s:%s", logType, environment)
	}
	// Iterate through received messages to extract metadata
	var uuids, hosts, names, users, osqueryusers, hashes, dhashes, osqueryversions []string
	for _, l := range logs {
		uuids = append(uuids, l.HostIdentifier)
		hosts = append(hosts, l.Decorations.Hostname)
		names = append(names, l.Decorations.LocalHostname)
		users = append(users, l.Decorations.Username)
		osqueryusers = append(osqueryusers, l.Decorations.OsqueryUser)
		hashes = append(hashes, l.Decorations.ConfigHash)
		dhashes = append(dhashes, l.Decorations.DaemonHash)
		osqueryversions = append(osqueryversions, l.Version)
	}
	if debug {
		log.Printf("metadata and dispatch for %s", uniq(uuids)[0])
	}
	// FIXME it only uses the first element from the []string that uniq returns
	metadata := nodes.NodeMetadata{
		IPAddress:      ipaddress,
		Username:       uniq(users)[0],
		OsqueryUser:    uniq(osqueryusers)[0],
		Hostname:       uniq(hosts)[0],
		Localname:      uniq(names)[0],
		ConfigHash:     uniq(hashes)[0],
		DaemonHash:     uniq(dhashes)[0],
		OsqueryVersion: uniq(osqueryversions)[0],
		BytesReceived:  dataLen,
	}
	// Dispatch logs and update metadata
	l.DispatchLogs(data, uniq(uuids)[0], logType, environment, metadata, debug)
}

// ProcessLogQueryResult - Helper to process on-demand query result logs
func (l *LoggerTLS) ProcessLogQueryResult(queriesWrite types.QueryWriteRequest, environment string, debug bool) {
	// Retrieve node
	node, err := l.Nodes.GetByKey(queriesWrite.NodeKey)
	if err != nil {
		log.Printf("error retrieving node %s", err)
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
		// Update internal metrics per query
		var err error
		if queriesWrite.Statuses[q] != 0 {
			err = l.Queries.IncError(q)
		} else {
			err = l.Queries.IncExecution(q)
		}
		if err != nil {
			log.Printf("error updating query %s", err)
		}
		// Add a record for this query
		if err := l.Queries.TrackExecution(q, node.UUID, queriesWrite.Statuses[q]); err != nil {
			log.Printf("error adding query execution %s", err)
		}
		// Check if query is completed
		if err := l.Queries.VerifyComplete(q); err != nil {
			log.Printf("error verifying and completing query %s", err)
		}
	}
}
