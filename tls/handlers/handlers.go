package handlers

import (
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
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

// TLSResponse to be returned to requests
type TLSResponse struct {
	Message string `json:"message"`
}

// Option to pass to creator
type Option func(*HandlersTLS)

// WithEnvs to pass environment as option
func WithEnvs(envs *environments.Environment) Option {
	return func(h *HandlersTLS) {
		h.Envs = envs
	}
}

// WithEnvsMap to pass environment as option
func WithEnvsMap(envsmap *environments.MapEnvironments) Option {
	return func(h *HandlersTLS) {
		h.EnvsMap = envsmap
	}
}

// WithSettings to pass environment as option
func WithSettings(settings *settings.Settings) Option {
	return func(h *HandlersTLS) {
		h.Settings = settings
	}
}

// WithSettingsMap to pass environment as option
func WithSettingsMap(settingsmap *settings.MapSettings) Option {
	return func(h *HandlersTLS) {
		h.SettingsMap = settingsmap
	}
}

// WithNodes to pass environment as option
func WithNodes(nodes *nodes.NodeManager) Option {
	return func(h *HandlersTLS) {
		h.Nodes = nodes
	}
}

// WithTags to pass environment as option
func WithTags(tags *tags.TagManager) Option {
	return func(h *HandlersTLS) {
		h.Tags = tags
	}
}

// WithQueries to pass environment as option
func WithQueries(queries *queries.Queries) Option {
	return func(h *HandlersTLS) {
		h.Queries = queries
	}
}

// WithCarves to pass environment as option
func WithCarves(carves *carves.Carves) Option {
	return func(h *HandlersTLS) {
		h.Carves = carves
	}
}

// WithMetrics to pass environment as option
func WithMetrics(metrics *metrics.Metrics) Option {
	return func(h *HandlersTLS) {
		h.Metrics = metrics
	}
}

// WithLogs to pass environment as option
func WithLogs(logs *logging.LoggerTLS) Option {
	return func(h *HandlersTLS) {
		h.Logs = logs
	}
}

// CreateHandlersTLS to initialize the TLS handlers struct
func CreateHandlersTLS(opts ...Option) *HandlersTLS {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricEnrollErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Check if environment accept enrolls
	if !env.AcceptEnrolls {
		h.Inc(metricEnrollErr)
		log.Printf("environment not enrolling %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.EnrollRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
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
		newNode = nodeFromEnroll(t, env.Name, utils.GetIP(r), nodeKey, len(body))
		// Check if UUID exists already, if so archive node and enroll new node
		if h.Nodes.CheckByUUIDEnv(t.HostIdentifier, env.Name) {
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
				// TODO autotag node based on existing or newly created tags
				if err := h.Tags.TagNode(env.Name, newNode); err != nil {
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
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricConfigErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.ConfigRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error recording IP address %v", err)
		}
		// Refresh last config for node
		if err := h.Nodes.ConfigRefresh(node, ip, len(body)); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error refreshing last config %v", err)
		}
		response = []byte(env.Configuration)
	} else {
		response = types.ConfigResponse{NodeInvalid: true}
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricLogErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Check if body is compressed, if so, uncompress
	if r.Header.Get("Content-Encoding") == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			h.Inc(metricLogErr)
			log.Printf("error decoding gzip body %v", err)
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				h.Inc(metricLogErr)
				log.Printf("Failed to close body %v", err)
			}
		}()
	}
	// Debug HTTP here so the body will be uncompressed
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Extract POST body and decode JSON
	var t types.LogRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricLogErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
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
		go h.Logs.ProcessLogs(t.Data, t.LogType, env.Name, utils.GetIP(r), len(body), (*h.EnvsMap)[env.Name].DebugHTTP)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response := types.LogResponse{NodeInvalid: nodeInvalid}
	// Debug
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricReadErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryReadRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid, accelerate bool
	qs := make(queries.QueryReadQueries)
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error recording IP address %v", err)
		}
		nodeInvalid = false
		qs, accelerate, err = h.Queries.NodeQueries(node)
		if err != nil {
			h.Inc(metricReadErr)
			log.Printf("error getting queries from db %v", err)
		}
		// Refresh last query read request
		if err := h.Nodes.QueryReadRefresh(node, ip, len(body)); err != nil {
			h.Inc(metricReadErr)
			log.Printf("error refreshing last query read %v", err)
		}
	} else {
		log.Printf("GetByKey %v", err)
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
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricWriteErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryWriteRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error recording IP address %v", err)
		}
		nodeInvalid = false
		for name, c := range t.Queries {
			var carves []types.QueryCarveScheduled
			if err := json.Unmarshal(c, &carves); err == nil {
				for _, cc := range carves {
					if cc.Carve == "1" {
						if err := h.ProcessCarveWrite(cc, name, t.NodeKey, env.Name); err != nil {
							h.Inc(metricWriteErr)
							log.Printf("error scheduling carve %v", err)
						}
					}
				}
			}
		}
		if err := h.Nodes.QueryWriteRefresh(node, ip, len(body)); err != nil {
			h.Inc(metricReadErr)
			log.Printf("error refreshing last query write %v", err)
		}
		// Process submitted results and mark query as processed
		go h.Logs.ProcessLogQueryResult(t, env.Name, (*h.EnvsMap)[env.Name].DebugHTTP)
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response := types.QueryWriteResponse{NodeInvalid: nodeInvalid}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Retrieve type of script
	script, ok := vars["script"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Script is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Retrieve SecretPath variable
	secretPath, ok := vars["secretpath"]
	if !ok {
		h.Inc(metricOnelinerErr)
		log.Println("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, "enroll") {
		if !h.checkValidEnrollSecretPath(env, secretPath) {
			h.Inc(metricOnelinerErr)
			log.Println("Invalid secret path for enrolling")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredEnrollSecretPath(env) {
			h.Inc(metricOnelinerErr)
			log.Println("Expired enrolling path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	} else if strings.HasPrefix(script, "remove") {
		if !h.checkValidRemoveSecretPath(env, secretPath) {
			h.Inc(metricOnelinerErr)
			log.Println("Invalid secret path for removing")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredRemoveSecretPath(env) {
			h.Inc(metricOnelinerErr)
			log.Println("Expired removing path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript("osctrl-"+env.Name, script, env)
	if err != nil {
		h.Inc(metricOnelinerErr)
		log.Printf("error getting script %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Error generating script"})
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricInitErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveInitRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	initCarve := false
	var carveSessionID string
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error recording IP address %v", err)
		}
		initCarve = true
		carveSessionID = generateCarveSessionID()
		// Process carve init
		if err := h.ProcessCarveInit(t, carveSessionID, env.Name); err != nil {
			h.Inc(metricInitErr)
			log.Printf("error procesing carve init %v", err)
			initCarve = false
		}
		// Refresh last carve request
		if err := h.Nodes.CarveRefresh(node, ip, len(body)); err != nil {
			h.Inc(metricReadErr)
			log.Printf("error refreshing last carve init %v", err)
		}
	}
	// Prepare response
	response := types.CarveInitResponse{Success: initCarve, SessionID: carveSessionID}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
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
	envVar, ok := vars["environment"]
	if !ok {
		h.Inc(metricBlockErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveBlockRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricEnrollErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	blockCarve := false
	// Check if provided session_id matches with the request_id (carve query name)
	if carve, err := h.Carves.GetCheckCarve(t.SessionID, t.RequestID); err == nil {
		blockCarve = true
		// Process received block
		go h.ProcessCarveBlock(t, env.Name)
		// Refresh last carve request
		if err := h.Nodes.CarveRefreshByUUID(carve.UUID, utils.GetIP(r), len(body)); err != nil {
			h.Inc(metricReadErr)
			log.Printf("error refreshing last carve init %v", err)
		}
	}
	// Prepare response
	response := types.CarveBlockResponse{Success: blockCarve}
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Printf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricBlockOK)
}
