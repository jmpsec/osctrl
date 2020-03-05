package main

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/utils"
)

const (
	metricEnrollReq   = "enroll-req"
	metricEnrollErr   = "enroll-err"
	metricEnrollOK    = "enroll-ok"
	metricLogReq      = "log-req"
	metricLogErr      = "log-err"
	metricLogOK       = "log-ok"
	metricConfigReq   = "config-req"
	metricConfigErr   = "config-err"
	metricConfigOK    = "config-ok"
	metricReadReq     = "read-req"
	metricReadErr     = "read-err"
	metricReadOK      = "read-ok"
	metricWriteReq    = "write-req"
	metricWriteErr    = "write-err"
	metricWriteOK     = "write-ok"
	metricInitReq     = "init-req"
	metricInitErr     = "init-err"
	metricInitOK      = "init-ok"
	metricBlockReq    = "block-req"
	metricBlockErr    = "block-err"
	metricBlockOK     = "block-ok"
	metricHealthReq   = "health-req"
	metricHealthOK    = "health-ok"
	metricOnelinerReq = "oneliner-req"
	metricOnelinerErr = "oneliner-err"
	metricOnelinerOk  = "oneliner-ok"
)

// Handler to be used as health check
func okHTTPHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("💥"))
}

// Handle health requests
func healthHTTPHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricHealthReq)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("✅"))
	incMetric(metricHealthOK)
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	incMetric(metricLogOK)
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
	var nodeInvalid, accelerate bool
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
		qs, accelerate, err = queriesmgr.NodeQueries(node)
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
		accelerate = false
	}
	// Prepare response and serialize queries
	if accelerate {
		sAccelerate := int(settingsmap[settings.AcceleratedSeconds].Integer)
		response, err = json.Marshal(types.AcceleratedQueryReadResponse{Queries: qs, Accelerate: sAccelerate, NodeInvalid: nodeInvalid})
	} else {
		response, err = json.Marshal(types.QueryReadResponse{Queries: qs, NodeInvalid: nodeInvalid})
	}
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	incMetric(metricWriteOK)
}

// Function to handle the endpoint for quick enrollment script distribution
func quickEnrollHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricOnelinerReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricOnelinerErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricOnelinerErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, envsmap[env].DebugHTTP, true)
	e, err := envs.Get(env)
	if err != nil {
		incMetric(metricOnelinerErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Retrieve type of script
	script, ok := vars["script"]
	if !ok {
		incMetric(metricOnelinerErr)
		log.Println("Script is missing")
		return
	}
	// Retrieve SecretPath variable
	secretPath, ok := vars["secretpath"]
	if !ok {
		incMetric(metricOnelinerErr)
		log.Println("Path is missing")
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, "enroll") {
		if !checkValidEnrollSecretPath(env, secretPath) {
			incMetric(metricOnelinerErr)
			log.Println("Invalid Path")
			return
		}
	} else if strings.HasPrefix(script, "remove") {
		if !checkValidRemoveSecretPath(env, secretPath) {
			incMetric(metricOnelinerErr)
			log.Println("Invalid Path")
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript(projectName, script, e)
	if err != nil {
		incMetric(metricOnelinerErr)
		log.Printf("error getting script %v", err)
		return
	}
	// Send response
	utils.HTTPResponse(w, utils.TextPlainUTF8, http.StatusOK, []byte(quickScript))
	incMetric(metricOnelinerOk)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
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
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	incMetric(metricBlockOK)
}
