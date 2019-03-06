package main

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/javuto/osctrl/context"
	"github.com/javuto/osctrl/nodes"
	"github.com/javuto/osctrl/queries"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// TextPlain for Content-Type headers
const TextPlain string = "text/plain"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// TextPlainUTF8 for Content-Type headers, UTF charset
const TextPlainUTF8 string = TextPlain + "; charset=UTF-8"

// Handler to be used as health check
func okHTTPHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceName), false)
	// Send response
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("💥"))
}

// Handle testing requests
func testingHTTPHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("test"))
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("oh no..."))
}

// Function to handle the enroll requests from osquery nodes
func enrollHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	var response []byte
	// Retrieve context variable
	vars := mux.Vars(r)
	context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Decode read POST body
	var t EnrollRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Printf("error parsing POST body %v", err)
	}
	// Check if received secret is valid
	var nodeKey string
	var newNode nodes.OsqueryNode
	nodeInvalid := true
	if checkValidSecret(t.EnrollSecret, context) {
		// Generate node_key using UUID as entropy
		nodeKey = generateNodeKey(t.HostIdentifier)
		newNode = nodeFromEnroll(t, context, r.Header.Get("X-Real-IP"), nodeKey)
		// Check if UUID exists already, if so archive node and enroll new node
		if nodesmgr.CheckByUUID(t.HostIdentifier) {
			err := nodesmgr.Archive(t.HostIdentifier, "exists")
			if err != nil {
				log.Printf("error archiving node %v", err)
			}
			// Update existing with new enroll data
			err = nodesmgr.UpdateByUUID(newNode, t.HostIdentifier)
			if err != nil {
				log.Printf("error updating existing node %v", err)
			} else {
				nodeInvalid = false
			}
		} else { // New node, persist it
			err := nodesmgr.Create(newNode)
			if err != nil {
				log.Printf("error creating node %v", err)
			} else {
				nodeInvalid = false
			}
		}
	} else {
		log.Printf("error invalid enrolling secret %s", t.EnrollSecret)
	}
	// Prepare response
	response, err = json.Marshal(EnrollResponse{NodeKey: nodeKey, NodeInvalid: nodeInvalid})
	if err != nil {
		log.Printf("error formating response %v", err)
		return
	}
	// Debug HTTP
	if config.DebugHTTP(serviceName) {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// Function to handle the configuration requests from osquery nodes
func configHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	var response []byte
	// Retrieve context variable
	vars := mux.Vars(r)
	context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Get context
	ctx, err := ctxs.Get(context)
	if err != nil {
		log.Printf("error getting context %v", err)
		return
	}
	// Decode read POST body
	var t ConfigRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		err = nodesmgr.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			log.Printf("error updating IP address %v", err)
		}
		// Refresh last config for node
		err = nodesmgr.RefreshLastConfig(t.NodeKey)
		if err != nil {
			log.Printf("error refreshing last config %v", err)
		}
		response = []byte(ctx.Configuration)
	} else {
		response, err = json.Marshal(ConfigResponse{NodeInvalid: true})
		if err != nil {
			log.Printf("error formating response %v", err)
			return
		}
	}
	// Debug HTTP
	if config.DebugHTTP(serviceName) {
		log.Printf("Configuration: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// Function to handle the log requests from osquery nodes, both status and results
func logHandler(w http.ResponseWriter, r *http.Request) {
	var response []byte
	// Retrieve context variable
	vars := mux.Vars(r)
	context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Check if body is compressed, if so, uncompress
	var err error
	if r.Header.Get("Content-Encoding") == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			log.Printf("error decoding gzip body %v", err)
		}
		defer r.Body.Close()
	}
	// Debug HTTP here so the body will be uncompressed
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Extract POST body and decode JSON
	var t LogRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Printf("error parsing POST body %v", err)
	}
	defer r.Body.Close()
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		nodeInvalid = false
		// Process logs and update metadata
		processLogs(t.Data, t.LogType, context, r.Header.Get("X-Real-IP"))
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response, err = json.Marshal(LogResponse{NodeInvalid: nodeInvalid})
	if err != nil {
		log.Printf("error preparing response %v", err)
		response = []byte("")
	}
	// Debug
	if config.DebugHTTP(serviceName) {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// Helper to process logs
func processLogs(data json.RawMessage, logType, context, ipaddress string) {
	// Parse log to extract metadata
	var logs []LogGenericData
	err := json.Unmarshal(data, &logs)
	if err != nil {
		log.Printf("error parsing log %s %v", string(data), err)
	}
	// Iterate through received messages to extract metadata
	var uuids, hosts, names, users, osqueryusers, hashes, osqueryversions []string
	for _, l := range logs {
		uuids = append(uuids, l.HostIdentifier)
		hosts = append(hosts, l.Decorations.Hostname)
		names = append(names, l.Decorations.LocalHostname)
		users = append(users, l.Decorations.Username)
		osqueryusers = append(osqueryusers, l.Decorations.OsqueryUser)
		hashes = append(hashes, l.Decorations.ConfigHash)
		osqueryversions = append(osqueryversions, l.Version)
	}
	// FIXME it only uses the first element from the []string that uniq returns
	uuid := uniq(uuids)[0]
	user := uniq(users)[0]
	osqueryuser := uniq(osqueryusers)[0]
	host := uniq(hosts)[0]
	name := uniq(names)[0]
	hash := uniq(hashes)[0]
	osqueryversion := uniq(osqueryversions)[0]
	// Dispatch logs and update metadata
	dispatchLogs(data, uuid, ipaddress, user, osqueryuser, host, name, hash, osqueryversion, logType, context)
}

// Helper to dispatch logs
func dispatchLogs(data []byte, UUID, ipaddress, user, osqueryuser, hostname, localname, hash, osqueryversion, logType, context string) {
	// Send data to storage
	if logConfig.Graylog {
		go graylogSend(data, context, logType, UUID, logConfig.GraylogCfg)
	}
	if logConfig.Splunk {
		go splunkSend(data, context, logType, UUID, logConfig.SplunkCfg)
	}
	if logConfig.Postgres {
		go postgresLog(data, context, logType, UUID)
	}
	if logConfig.Stdout {
		log.Printf("LOG: %s from context %s : %s", logType, context, string(data))
	}
	// Use metadata to update record
	err := nodesmgr.UpdateMetadataByUUID(user, osqueryuser, hostname, localname, ipaddress, hash, osqueryversion, UUID)
	if err != nil {
		log.Printf("error updating metadata %s", err)
	}
	// Refresh last logging request
	if logType == statusLog {
		err := nodesmgr.RefreshLastStatus(UUID)
		if err != nil {
			log.Printf("error refreshing last status %v", err)
		}
	}
	if logType == resultLog {
		err := nodesmgr.RefreshLastResult(UUID)
		if err != nil {
			log.Printf("error refreshing last result %v", err)
		}
	}
}

// Helper to dispatch queries
func dispatchQueries(queryData QueryWriteData, node nodes.OsqueryNode) {
	// Prepare data to send
	data, err := json.Marshal(queryData)
	if err != nil {
		log.Printf("error preparing data %v", err)
	}
	// Send data to storage
	if logConfig.Graylog {
		go graylogSend(data, node.Context, queryLog, node.UUID, logConfig.GraylogCfg)
	}
	if logConfig.Splunk {
		go splunkSend(data, node.Context, queryLog, node.UUID, logConfig.SplunkCfg)
	}
	if logConfig.Postgres {
		go postgresQuery(data, queryData.Name, node, queryData.Status)
	}
	if logConfig.Stdout {
		log.Printf("QUERY: %s from context %s : %s", "query", node.Context, string(data))
	}
	// Refresh last query write request
	err = nodesmgr.RefreshLastQueryWrite(node.UUID)
	if err != nil {
		log.Printf("error refreshing last query write %v", err)
	}
}

// Function to handle on-demand queries to osquery nodes
func queryReadHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Retrieve context variable
	vars := mux.Vars(r)
	context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Decode read POST body
	var response []byte
	var t QueryReadRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Printf("error parsing POST body %v", err)
	}
	var nodeInvalid bool
	qs := make(queries.QueryReadQueries)
	// Lookup node by node_key
	node, err := nodesmgr.GetByKey(t.NodeKey)
	if err == nil {
		err = nodesmgr.UpdateIPAddress(r.Header.Get("X-Real-IP"), node)
		if err != nil {
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		qs, err = queriesmgr.NodeQueries(node)
		if err != nil {
			log.Printf("error getting queries from db %v", err)
		}
		// Refresh last query read request
		err = nodesmgr.RefreshLastQueryRead(t.NodeKey)
		if err != nil {
			log.Printf("error refreshing last query read %v", err)
		}
	} else {
		nodeInvalid = true
	}
	// Prepare response for invalid key
	response, err = json.Marshal(QueryReadResponse{Queries: qs, NodeInvalid: nodeInvalid})
	if err != nil {
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if config.DebugHTTP(serviceName) {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// Function to handle distributed query results from osquery nodes
func queryWriteHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Retrieve context variable
	vars := mux.Vars(r)
	context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Decode read POST body
	var response []byte
	var t QueryWriteRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		log.Printf("error parsing POST body %v", err)
	}
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		err = nodesmgr.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		// Process submitted results
		go processLogQueryResult(t.Queries, t.Statuses, t.NodeKey, context)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response, err = json.Marshal(QueryWriteResponse{NodeInvalid: nodeInvalid})
	if err != nil {
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if config.DebugHTTP(serviceName) {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// Helper to process on-demand query result logs
func processLogQueryResult(queries QueryWriteQueries, statuses QueryWriteStatuses, nodeKey string, context string) {
	// Retrieve node
	node, err := nodesmgr.GetByKey(nodeKey)
	if err != nil {
		log.Printf("error retrieving node %s", err)
	}
	// Tap into results so we can update internal metrics
	for q, r := range queries {
		// Dispatch query name, result and status
		d := QueryWriteData{
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
		err = queriesmgr.TrackExecution(q, node.UUID, statuses[q])
		if err != nil {
			log.Printf("error adding query execution %s", err)
		}
	}
}

// Function to handle the endpoint for quick enrollment script distribution
func quickEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP
	debugHTTPDump(r, config.DebugHTTP(serviceName), true)
	// Retrieve context variable
	vars := mux.Vars(r)
	_context, ok := vars["context"]
	if !ok {
		log.Println("Context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(_context) {
		log.Printf("error unknown context (%s)", _context)
		return
	}
	ctx, err := ctxs.Get(_context)
	if err != nil {
		log.Printf("error getting context %v", err)
		return
	}
	// Retrieve SecretPath variable
	secretPath, ok := vars["secretpath"]
	if !ok {
		log.Println("Path is missing")
		return
	}
	// Check if provided SecretPath is valid and if so, prepare script
	if !checkValidSecretPath(_context, secretPath) {
		log.Println("Invalid Path")
		return
	}
	// Retrieve type of script
	addScript, ok := vars["script"]
	if !ok {
		log.Println("Script is missing")
		return
	}
	// Prepare response with the script
	quickScript, err := context.QuickAddScript(projectName, addScript, ctx, tlsPath)
	if err != nil {
		log.Printf("error getting script %v", err)
		return
	}
	// Send response
	w.Header().Set("Content-Type", TextPlainUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(quickScript))
}
