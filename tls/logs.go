package main

import (
	"encoding/json"
	"log"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/types"
)

// Helper to process logs
func processLogs(data json.RawMessage, logType, environment, ipaddress string) {
	// Parse log to extract metadata
	var logs []types.LogGenericData
	err := json.Unmarshal(data, &logs)
	if err != nil {
		// FIXME metrics for this
		log.Printf("error parsing log %s %v", string(data), err)
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
	// FIXME it only uses the first element from the []string that uniq returns
	uuid := uniq(uuids)[0]
	user := uniq(users)[0]
	osqueryuser := uniq(osqueryusers)[0]
	host := uniq(hosts)[0]
	name := uniq(names)[0]
	hash := uniq(hashes)[0]
	dhash := uniq(dhashes)[0]
	osqueryversion := uniq(osqueryversions)[0]
	// Dispatch logs and update metadata
	dispatchLogs(data, uuid, ipaddress, user, osqueryuser, host, name, hash, dhash, osqueryversion, logType, environment)
}

// Helper to dispatch logs
func dispatchLogs(data []byte, uuid, ipaddress, user, osqueryuser, hostname, localname, hash, dhash, osqueryversion, logType, environment string) {
	// Use metadata to update record
	if err := nodesmgr.UpdateMetadataByUUID(user, osqueryuser, hostname, localname, ipaddress, hash, dhash, osqueryversion, uuid); err != nil {
		log.Printf("error updating metadata %s", err)
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if envsmap[environment].DebugHTTP {
		log.Printf("dispatching logs to %s", tlsConfig.Logging)
	}
	loggerTLS.Log(
		logType,
		data,
		environment,
		uuid,
		envsmap[environment].DebugHTTP)
	// Refresh last logging request
	if logType == types.StatusLog {
		err := nodesmgr.RefreshLastStatus(uuid)
		if err != nil {
			log.Printf("error refreshing last status %v", err)
		}
	}
	if logType == types.ResultLog {
		if err := nodesmgr.RefreshLastResult(uuid); err != nil {
			log.Printf("error refreshing last result %v", err)
		}
	}
}

// Helper to dispatch queries
func dispatchQueries(queryData types.QueryWriteData, node nodes.OsqueryNode) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Printf("error preparing data %v", err)
	}
	// Refresh last query write request
	if err := nodesmgr.RefreshLastQueryWrite(node.UUID); err != nil {
		log.Printf("error refreshing last query write %v", err)
	}
	// Send data to storage
	// FIXME allow multiple types of logging
	if envsmap[node.Environment].DebugHTTP {
		log.Printf("dispatching queries to %s", tlsConfig.Logging)
	}
	loggerTLS.QueryLog(
		types.QueryLog,
		data,
		node.Environment,
		node.UUID,
		queryData.Name,
		queryData.Status,
		envsmap[node.Environment].DebugHTTP)
}

// Helper to process on-demand query result logs
func processLogQueryResult(queries types.QueryWriteQueries, statuses types.QueryWriteStatuses, nodeKey string, environment string) {
	// Retrieve node
	node, err := nodesmgr.GetByKey(nodeKey)
	if err != nil {
		log.Printf("error retrieving node %s", err)
	}
	// Tap into results so we can update internal metrics
	for q, r := range queries {
		// Dispatch query name, result and status
		d := types.QueryWriteData{
			Name:   q,
			Result: r,
			Status: statuses[q],
		}
		go dispatchQueries(d, node)
		// Update internal metrics per query
		var err error
		if statuses[q] != 0 {
			err = queriesmgr.IncError(q)
		} else {
			err = queriesmgr.IncExecution(q)
		}
		if err != nil {
			log.Printf("error updating query %s", err)
		}
		// Add a record for this query
		if err := queriesmgr.TrackExecution(q, node.UUID, statuses[q]); err != nil {
			log.Printf("error adding query execution %s", err)
		}
		// Check if query is completed
		if err := queriesmgr.VerifyComplete(q); err != nil {
			log.Printf("error verifying and completing query %s", err)
		}
	}
}
