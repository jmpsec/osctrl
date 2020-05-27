package handlers

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
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

// HandlersTLS to keep all handlers for TLS
type HandlersTLS struct {
	Envs        *environments.Environment
	EnvsMap     *environments.MapEnvironments
	Nodes       *nodes.NodeManager
	Tags        *tags.TagManager
	Queries     *queries.Queries
	Carves      *carves.Carves
	Settings    *settings.Settings
	SettingsMap *settings.MapSettings
	Metrics     *metrics.Metrics
	Logs        *logging.LoggerTLS
}

type HandlersOption func(*HandlersTLS)

func WithEnvs(envs *environments.Environment) HandlersOption {
	return func(h *HandlersTLS) {
		h.Envs = envs
	}
}

func WithEnvsMap(envsmap *environments.MapEnvironments) HandlersOption {
	return func(h *HandlersTLS) {
		h.EnvsMap = envsmap
	}
}

func WithSettings(settings *settings.Settings) HandlersOption {
	return func(h *HandlersTLS) {
		h.Settings = settings
	}
}

func WithSettingsMap(settingsmap *settings.MapSettings) HandlersOption {
	return func(h *HandlersTLS) {
		h.SettingsMap = settingsmap
	}
}

func WithNodes(nodes *nodes.NodeManager) HandlersOption {
	return func(h *HandlersTLS) {
		h.Nodes = nodes
	}
}

func WithTags(tags *tags.TagManager) HandlersOption {
	return func(h *HandlersTLS) {
		h.Tags = tags
	}
}

func WithQueries(queries *queries.Queries) HandlersOption {
	return func(h *HandlersTLS) {
		h.Queries = queries
	}
}

func WithCarves(carves *carves.Carves) HandlersOption {
	return func(h *HandlersTLS) {
		h.Carves = carves
	}
}

func WithMetrics(metrics *metrics.Metrics) HandlersOption {
	return func(h *HandlersTLS) {
		h.Metrics = metrics
	}
}

func WithLogs(logs *logging.LoggerTLS) HandlersOption {
	return func(h *HandlersTLS) {
		h.Logs = logs
	}
}

// CreateHandlersTLS to initialize the TLS handlers struct
func CreateHandlersTLS(opts ...HandlersOption) *HandlersTLS {
	h := &HandlersTLS{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Inc - Helper to send metrics if it is enabled
func (h *HandlersTLS) Inc(name string) {
	if h.Metrics != nil && h.Settings.ServiceMetrics(settings.ServiceTLS) {
		h.Metrics.Inc(name)
	}
}

// RootHandler to be used as health check
func (h *HandlersTLS) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("💥"))
}

// HealthHandler for health requests
func (h *HandlersTLS) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricHealthReq)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte("✅"))
	h.Inc(metricHealthOK)
}

// ErrorHandler for error requests
func (h *HandlersTLS) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
}

// EnrollHandler - Function to handle the enroll requests from osquery nodes
func (h *HandlersTLS) EnrollHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricEnrollReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricEnrollErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricEnrollErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Decode read POST body
	var t types.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if received secret is valid
	var nodeKey string
	var newNode nodes.OsqueryNode
	nodeInvalid := true
	if h.checkValidSecret(t.EnrollSecret, env) {
		// Generate node_key using UUID as entropy
		nodeKey = generateNodeKey(t.HostIdentifier, time.Now())
		newNode = nodeFromEnroll(t, env, r.Header.Get("X-Real-IP"), nodeKey)
		// Check if UUID exists already, if so archive node and enroll new node
		if h.Nodes.CheckByUUIDEnv(t.HostIdentifier, env) {
			if err := h.Nodes.Archive(t.HostIdentifier, "exists"); err != nil {
				h.Inc(metricEnrollErr)
				log.Printf("error archiving node %v", err)
			}
			// Update existing with new enroll data
			if err := h.Nodes.UpdateByUUID(newNode, t.HostIdentifier); err != nil {
				h.Inc(metricEnrollErr)
				log.Printf("error updating existing node %v", err)
			} else {
				nodeInvalid = false
			}
		} else { // New node, persist it
			if err := h.Nodes.Create(&newNode); err != nil {
				h.Inc(metricEnrollErr)
				log.Printf("error creating node %v", err)
			} else {
				nodeInvalid = false
				if err := h.Tags.TagNode(env, newNode); err != nil {
					h.Inc(metricEnrollErr)
					log.Printf("error tagging node %v", err)
				}
			}
		}
	} else {
		h.Inc(metricEnrollErr)
		log.Printf("error invalid enrolling secret %s", t.EnrollSecret)
	}
	response := types.EnrollResponse{NodeKey: nodeKey, NodeInvalid: nodeInvalid}
	// Debug HTTP
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricEnrollOK)
}

// ConfigHandler - Function to handle the configuration requests from osquery nodes
func (h *HandlersTLS) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricConfigReq)
	var response interface{}
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricConfigErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricConfigErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Get environment
	e, err := h.Envs.Get(env)
	if err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Decode read POST body
	var t types.ConfigRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided node_key is valid and if so, update node
	if h.Nodes.CheckByKey(t.NodeKey) {
		err = h.Nodes.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey)
		if err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error updating IP address %v", err)
		}
		// Refresh last config for node
		err = h.Nodes.RefreshLastConfig(t.NodeKey)
		if err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error refreshing last config %v", err)
		}
		response = []byte(e.Configuration)
	} else {
		response = types.ConfigResponse{NodeInvalid: true}
	}
	// Debug HTTP
	if (*h.EnvsMap)[env].DebugHTTP {
		if x, ok := response.([]byte); ok {
			log.Printf("Configuration: %s", string(x))
		} else {
			log.Printf("Configuration: %+v", response)
		}
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricConfigOK)
}

// LogHandler - Function to handle the log requests from osquery nodes, both status and results
func (h *HandlersTLS) LogHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricLogReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricLogErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricLogErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Check if body is compressed, if so, uncompress
	var err error
	if r.Header.Get("Content-Encoding") == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			h.Inc(metricLogErr)
			log.Printf("error decoding gzip body %v", err)
		}
		//defer r.Body.Close()
		defer func() {
			if err := r.Body.Close(); err != nil {
				h.Inc(metricLogErr)
				log.Printf("Failed to close body %v", err)
			}
		}()
	}
	// Debug HTTP here so the body will be uncompressed
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Extract POST body and decode JSON
	var t types.LogRequest
	err = json.NewDecoder(r.Body).Decode(&t)
	if err != nil {
		h.Inc(metricLogErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	//defer r.Body.Close()
	defer func() {
		if err := r.Body.Close(); err != nil {
			h.Inc(metricLogErr)
			log.Printf("Failed to close body %v", err)
		}
	}()
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if h.Nodes.CheckByKey(t.NodeKey) {
		nodeInvalid = false
		// Process logs and update metadata
		h.Logs.ProcessLogs(t.Data, t.LogType, env, r.Header.Get("X-Real-IP"), (*h.EnvsMap)[env].DebugHTTP)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response := types.LogResponse{NodeInvalid: nodeInvalid}
	// Debug
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricLogOK)
}

// QueryReadHandler - Function to handle on-demand queries to osquery nodes
func (h *HandlersTLS) QueryReadHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricReadReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricReadErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricReadErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryReadRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		h.Inc(metricReadErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid, accelerate bool
	qs := make(queries.QueryReadQueries)
	// Lookup node by node_key
	node, err := h.Nodes.GetByKey(t.NodeKey)
	if err == nil {
		err = h.Nodes.UpdateIPAddress(r.Header.Get("X-Real-IP"), node)
		if err != nil {
			h.Inc(metricReadErr)
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		qs, accelerate, err = h.Queries.NodeQueries(node)
		if err != nil {
			h.Inc(metricReadErr)
			log.Printf("error getting queries from db %v", err)
		}
		// Refresh last query read request
		err = h.Nodes.RefreshLastQueryRead(t.NodeKey)
		if err != nil {
			h.Inc(metricReadErr)
			log.Printf("error refreshing last query read %v", err)
		}
	} else {
		nodeInvalid = true
		accelerate = false
	}
	// Prepare response and serialize queries
	var response interface{}
	if accelerate {
		sAccelerate := int((*h.SettingsMap)[settings.AcceleratedSeconds].Integer)
		response = types.AcceleratedQueryReadResponse{Queries: qs, Accelerate: sAccelerate, NodeInvalid: nodeInvalid}
	} else {
		response = types.QueryReadResponse{Queries: qs, NodeInvalid: nodeInvalid}
	}
	// Debug HTTP
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricReadOK)
}

// QueryWriteHandler - Function to handle distributed query results from osquery nodes
func (h *HandlersTLS) QueryWriteHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricWriteReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricWriteErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricWriteErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		h.Inc(metricWriteErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if h.Nodes.CheckByKey(t.NodeKey) {
		if err := h.Nodes.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey); err != nil {
			h.Inc(metricWriteErr)
			log.Printf("error updating IP Address %v", err)
		}
		nodeInvalid = false
		// Process submitted results
		go h.Logs.ProcessLogQueryResult(t.Queries, t.Statuses, t.NodeKey, env, (*h.EnvsMap)[env].DebugHTTP)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response := types.QueryWriteResponse{NodeInvalid: nodeInvalid}
	// Debug HTTP
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricWriteOK)
}

// QuickEnrollHandler - Function to handle the endpoint for quick enrollment script distribution
func (h *HandlersTLS) QuickEnrollHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricOnelinerReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricOnelinerErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	e, err := h.Envs.Get(env)
	if err != nil {
		h.Inc(metricOnelinerErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Retrieve type of script
	script, ok := vars["script"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Script is missing")
		return
	}
	// Retrieve SecretPath variable
	secretPath, ok := vars["secretpath"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Path is missing")
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, "enroll") {
		if !h.checkValidEnrollSecretPath(env, secretPath) {
			h.Inc(metricOnelinerErr)
			log.Println("Invalid Path")
			return
		}
	} else if strings.HasPrefix(script, "remove") {
		if !h.checkValidRemoveSecretPath(env, secretPath) {
			h.Inc(metricOnelinerErr)
			log.Println("Invalid Path")
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript("osctrl-"+e.Name, script, e)
	if err != nil {
		h.Inc(metricOnelinerErr)
		log.Printf("error getting script %v", err)
		return
	}
	// Send response
	utils.HTTPResponse(w, utils.TextPlainUTF8, http.StatusOK, []byte(quickScript))
	h.Inc(metricOnelinerOk)
}

// CarveInitHandler - Function to handle the initialization of the file carver
// This function does not use go routines to handle requests because the session_id returned
// must be already created in the DB, otherwise block requests will fail.
func (h *HandlersTLS) CarveInitHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricInitReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricInitErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricInitErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveInitRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		h.Inc(metricInitErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	initCarve := false
	var carveSessionID string
	// Check if provided node_key is valid and if so, update node
	if h.Nodes.CheckByKey(t.NodeKey) {
		if err := h.Nodes.UpdateIPAddressByKey(r.Header.Get("X-Real-IP"), t.NodeKey); err != nil {
			h.Inc(metricInitErr)
			log.Printf("error updating IP Address %v", err)
		}
		initCarve = true
		carveSessionID = generateCarveSessionID()
		// Process carve init
		if err := h.ProcessCarveInit(t, carveSessionID, env); err != nil {
			h.Inc(metricInitErr)
			log.Printf("error procesing carve init %v", err)
			initCarve = false
		}
	}
	// Prepare response
	response := types.CarveInitResponse{Success: initCarve, SessionID: carveSessionID}
	// Debug HTTP
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricInitOK)
}

// CarveBlockHandler - Function to handle the blocks of the file carver
func (h *HandlersTLS) CarveBlockHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricBlockReq)
	// Retrieve environment variable
	vars := mux.Vars(r)
	env, ok := vars["environment"]
	if !ok {
		h.Inc(metricBlockErr)
		log.Println("Environment is missing")
		return
	}
	// Check if environment is valid
	if !h.Envs.Exists(env) {
		h.Inc(metricBlockErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	blockCarve := false
	// Check if provided session_id matches with the request_id (carve query name)
	if h.Carves.CheckCarve(t.SessionID, t.RequestID) {
		blockCarve = true
		// Process received block
		go h.ProcessCarveBlock(t, env)
	}
	// Prepare response
	response := types.CarveBlockResponse{Success: blockCarve}
	if (*h.EnvsMap)[env].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricBlockOK)
}
