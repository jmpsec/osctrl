package main

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
)

const (
	metricEnrollReq = "enroll-req"
	metricEnrollErr = "enroll-err"
	metricEnrollOK  = "enroll-ok"
	metricLogReq    = "log-req"
	metricLogErr    = "log-err"
	metricLogOK     = "log-ok"
	metricConfigReq = "config-req"
	metricConfigErr = "config-err"
	metricConfigOK  = "config-ok"
	metricReadReq   = "read-req"
	metricReadErr   = "read-err"
	metricReadOK    = "read-ok"
	metricWriteReq  = "write-req"
	metricWriteErr  = "write-err"
	metricWriteOK   = "write-ok"
	metricInitReq   = "init-req"
	metricInitErr   = "init-err"
	metricInitOK    = "init-ok"
	metricBlockReq  = "block-req"
	metricBlockErr  = "block-err"
	metricBlockOK   = "block-ok"
	metricHealthReq  = "health-req"
	metricHealthOK   = "health-ok"
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
	// Send response
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("💥"))
}

// Handle health requests
func healthHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("✅"))
	incMetric(metricHealthOK)
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("oh no..."))
}

// Function to handle the enroll requests from osquery nodes
func enrollHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricEnrollReq)
	var response []byte
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricEnrollErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricEnrollErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Decode read POST body
	var t types.EnrollRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricEnrollErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if received secret is valid
	var nodeKey string
	var newNode nodes.OsqueryNode
	nodeInvalid := true
	if checkValidSecret(t.EnrollSecret, env) {
		// Generate node_key using UUID as entropy
		nodeKey = generateNodeKey(t.HostIdentifier)
		newNode = nodeFromEnroll(t, env, r.Header.Get("X-Real-IP"), nodeKey)
		// Check if UUID exists already, if so archive node and enroll new node
		if nodesmgr.CheckByUUID(t.HostIdentifier) {
			err := nodesmgr.Archive(t.HostIdentifier, "exists")
			if err != nil {
				incMetric(metricEnrollErr)
				log.Printf("error archiving node %v", err)
			}
			// Update existing with new enroll data
			err = nodesmgr.UpdateByUUID(newNode, t.HostIdentifier)
			if err != nil {
				incMetric(metricEnrollErr)
				log.Printf("error updating existing node %v", err)
			} else {
				nodeInvalid = false
			}
		} else { // New node, persist it
			err := nodesmgr.Create(newNode)
			if err != nil {
				incMetric(metricEnrollErr)
				log.Printf("error creating node %v", err)
			} else {
				nodeInvalid = false
			}
		}
	} else {
		incMetric(metricEnrollErr)
		log.Printf("error invalid enrolling secret %s", t.EnrollSecret)
	}
	// Prepare response
	response, err = json.Marshal(types.EnrollResponse{NodeKey: nodeKey, NodeInvalid: nodeInvalid})
	if err != nil {
		log.Printf("error formating response %v", err)
		return
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricEnrollOK)
}

// Function to handle the configuration requests from osquery nodes
func configHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricConfigReq)
	var response []byte
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricConfigErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricConfigErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Get environment
	e, err := envs.Get(env)
	if err != nil {
		incMetric(metricConfigErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Decode read POST body
	var t types.ConfigRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		err = nodesmgr.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			incMetric(metricConfigErr)
			log.Printf("error updating IP address %v", err)
		}
		// Refresh last config for node
		err = nodesmgr.RefreshLastConfig(t.NodeKey)
		if err != nil {
			incMetric(metricConfigErr)
			log.Printf("error refreshing last config %v", err)
		}
		response = []byte(e.Configuration)
	} else {
		response, err = json.Marshal(types.ConfigResponse{NodeInvalid: true})
		if err != nil {
			incMetric(metricConfigErr)
			log.Printf("error formating response %v", err)
			return
		}
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Configuration: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricConfigOK)
}

// Function to handle the log requests from osquery nodes, both status and results
func logHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricLogReq)
	var response []byte
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricLogErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricLogErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Check if body is compressed, if so, uncompress
	var err error
	if r.Header.Get("Content-Encoding") == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			incMetric(metricLogErr)
			log.Printf("error decoding gzip body %v", err)
		}
		//defer r.Body.Close()
		defer func() {
			err := r.Body.Close()
			if err != nil {
				incMetric(metricLogErr)
				log.Printf("Failed to close body %v", err)
			}
		}()
	}
	// Debug HTTP here so the body will be uncompressed
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Extract POST body and decode JSON
	var t types.LogRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricLogErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	//defer r.Body.Close()
	defer func() {
		err := r.Body.Close()
		if err != nil {
			incMetric(metricLogErr)
			log.Printf("Failed to close body %v", err)
		}
	}()
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		nodeInvalid = false
		// Process logs and update metadata
		processLogs(t.Data, t.LogType, env, r.Header.Get("X-Real-IP"))
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response, err = json.Marshal(types.LogResponse{NodeInvalid: nodeInvalid})
	if err != nil {
		incMetric(metricLogErr)
		log.Printf("error preparing response %v", err)
		response = []byte("")
	}
	// Debug
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricLogOK)
}

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
	logsDispatcher(
		tlsConfig.Logging,
		logType,
		db,
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
	logsDispatcher(
		tlsConfig.Logging,
		types.QueryLog,
		db,
		data,
		node.Environment,
		node.UUID,
		queryData.Name,
		queryData.Status,
		envsmap[node.Environment].DebugHTTP)
}

// Function to handle on-demand queries to osquery nodes
func queryReadHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricReadReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricReadErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricReadErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Decode read POST body
	var response []byte
	var t types.QueryReadRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricReadErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid bool
	qs := make(queries.QueryReadQueries)
	// Lookup node by node_key
	node, err := nodesmgr.GetByKey(t.NodeKey)
	if err == nil {
		err = nodesmgr.UpdateIPAddress(r.Header.Get("X-Real-IP"), node)
		if err != nil {
			incMetric(metricReadErr)
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		qs, err = queriesmgr.NodeQueries(node)
		if err != nil {
			incMetric(metricReadErr)
			log.Printf("error getting queries from db %v", err)
		}
		// Refresh last query read request
		err = nodesmgr.RefreshLastQueryRead(t.NodeKey)
		if err != nil {
			incMetric(metricReadErr)
			log.Printf("error refreshing last query read %v", err)
		}
	} else {
		nodeInvalid = true
	}
	// Prepare response for invalid key
	response, err = json.Marshal(types.QueryReadResponse{Queries: qs, NodeInvalid: nodeInvalid})
	if err != nil {
		incMetric(metricReadErr)
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricReadOK)
}

// Function to handle distributed query results from osquery nodes
func queryWriteHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricWriteReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricWriteErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricWriteErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Decode read POST body
	var response []byte
	var t types.QueryWriteRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricWriteErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		err = nodesmgr.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			incMetric(metricWriteErr)
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		// Process submitted results
		go processLogQueryResult(t.Queries, t.Statuses, t.NodeKey, env)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response, err = json.Marshal(types.QueryWriteResponse{NodeInvalid: nodeInvalid})
	if err != nil {
		incMetric(metricWriteErr)
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricWriteOK)
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

// Function to handle the endpoint for quick enrollment script distribution
func quickEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// FIXME metrics
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	e, err := envs.Get(env)
	if err != nil {
		log.Printf("error getting environment %v", err)
		return
	}
	// Retrieve type of script
	script, ok := vars["script"]
	if !ok {
		log.Println("Script is missing")
		return
	}
	// Retrieve SecretPath variable
	secretPath, ok := vars["secretpath"]
	if !ok {
		log.Println("Path is missing")
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, "enroll") {
		if !checkValidEnrollSecretPath(env, secretPath) {
			log.Println("Invalid Path")
			return
		}
	} else if strings.HasPrefix(script, "remove") {
		if !checkValidRemoveSecretPath(env, secretPath) {
			log.Println("Invalid Path")
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript(projectName, script, e)
	if err != nil {
		log.Printf("error getting script %v", err)
		return
	}
	// Send response
	w.Header().Set("Content-Type", TextPlainUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(quickScript))
}

// Function to initialize a file carve from a node
func processCarveInit(req types.CarveInitRequest, sessionid, environment string) error {
	// Retrieve node
	node, err := nodesmgr.GetByKey(req.NodeKey)
	if err != nil {
		incMetric(metricInitErr)
		log.Printf("error retrieving node %s", err)
		return err
	}
	// Prepare carve to initialize
	carve := carves.CarvedFile{
		CarveID:         req.CarveID,
		RequestID:       req.RequestID,
		SessionID:       sessionid,
		UUID:            node.UUID,
		Environment:     environment,
		CarveSize:       req.CarveSize,
		BlockSize:       req.BlockSize,
		TotalBlocks:     req.BlockCount,
		CompletedBlocks: 0,
		Status:          carves.StatusInitialized,
	}
	// Create File Carve
	err = filecarves.CreateCarve(carve)
	if err != nil {
		incMetric(metricInitErr)
		log.Printf("error creating  CarvedFile %v", err)
		return err
	}
	return nil
}

// Function to process one block from a file carve
// FIXME it can be more efficient on db access
func processCarveBlock(req types.CarveBlockRequest, environment string) {
	// Prepare carve block
	block := carves.CarvedBlock{
		RequestID:   req.RequestID,
		SessionID:   req.SessionID,
		Environment: environment,
		BlockID:     req.BlockID,
		Data:        req.Data,
		Size:        len(req.Data),
	}
	// Create Block
	if err := filecarves.CreateBlock(block); err != nil {
		incMetric(metricBlockErr)
		log.Printf("error creating CarvedBlock %v", err)
	}
	// Bump block completion
	if err := filecarves.CompleteBlock(req.SessionID); err != nil {
		incMetric(metricBlockErr)
		log.Printf("error completing block %v", err)
	}
	// If it is completed, set status
	if filecarves.Completed(req.SessionID) {
		if err := filecarves.ChangeStatus(carves.StatusCompleted, req.SessionID); err != nil {
			incMetric(metricBlockErr)
			log.Printf("error completing carve %v", err)
		}
	} else {
		if err := filecarves.ChangeStatus(carves.StatusInProgress, req.SessionID); err != nil {
			incMetric(metricBlockErr)
			log.Printf("error progressing carve %v", err)
		}
	}
}

// Function to handle the initialization of the file carver
// This function does not use go routines to handle requests because the session_id returned
// must be already created in the DB, otherwise block requests will fail.
func carveInitHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricInitReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricInitErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricInitErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Decode read POST body
	var response []byte
	var t types.CarveInitRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricInitErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	initCarve := false
	var carveSessionID string
	// Check if provided node_key is valid and if so, update node
	if nodesmgr.CheckByKey(t.NodeKey) {
		err = nodesmgr.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			incMetric(metricInitErr)
			log.Printf("error updating IP Address %v", err)
		}
		initCarve = true
		carveSessionID = generateCarveSessionID()
		// Process carve init
		if err := processCarveInit(t, carveSessionID, env); err != nil {
			incMetric(metricInitErr)
			log.Printf("error procesing carve init %v", err)
			initCarve = false
		}
	}
	// Prepare response
	response, err = json.Marshal(types.CarveInitResponse{Success: initCarve, SessionID: carveSessionID})
	if err != nil {
		incMetric(metricInitErr)
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricInitOK)
}

// Function to handle the blocks of the file carver
func carveBlockHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricBlockReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricBlockErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricBlockErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	// Decode read POST body
	var response []byte
	var t types.CarveBlockRequest
	err := json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		incMetric(metricBlockErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	blockCarve := false
	// Check if provided session_id matches with the request_id (carve query name)
	if filecarves.CheckCarve(t.SessionID, t.RequestID) {
		blockCarve = true
		// Process received block
		go processCarveBlock(t, env)
	}
	// Prepare response
	response, err = json.Marshal(types.CarveBlockResponse{Success: blockCarve})
	if err != nil {
		incMetric(metricBlockErr)
		log.Printf("error formating response %v", err)
		response = []byte("")
	}
	// Debug HTTP
	if envsmap[env].DebugHTTP {
		log.Printf("Response: %s", string(response))
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
	incMetric(metricBlockOK)
}
