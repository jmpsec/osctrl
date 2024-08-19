package handlers

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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
	"github.com/jmpsec/osctrl/version"
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
	metricPackageReq  = "package-req"
	metricPackageErr  = "package-err"
	metricPackageOk   = "package-ok"
	metricFlagsReq    = "flags-req"
	metricFlagsErr    = "flags-err"
	metricFlagsOk     = "flags-ok"
	metricCertReq     = "cert-req"
	metricCertErr     = "cert-err"
	metricCertOk      = "cert-ok"
	metricScriptReq   = "script-req"
	metricScriptErr   = "script-err"
	metricScriptOk    = "script-ok"
	metricVerifyReq   = "verify-req"
	metricVerifyErr   = "verify-err"
	metricVerifyOk    = "verify-ok"
)

const (
	// osquery version
	defOsqueryVersion = version.OsqueryVersion
	// path for enroll packages
	enrollPackagesPath = "packages"
)

// Valid values for actions in handlers
var validAction = map[string]bool{
	settings.ScriptEnroll: true,
	settings.ScriptRemove: true,
}

// Valid values for enroll packages
var validEnrollPackage = map[string]bool{
	settings.PackageDeb: true,
	settings.PackageRpm: true,
	settings.PackageMsi: true,
	settings.PackagePkg: true,
}

// Valid values for platforms in handlers
var validPlatform = map[string]bool{
	settings.PlatformDarwin:  true,
	settings.PlatformLinux:   true,
	settings.PlatformWindows: true,
}

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
	Ingested    *metrics.IngestedManager
	Logs        *logging.LoggerTLS
}

// TLSResponse to be returned to requests
type TLSResponse struct {
	Message string `json:"message"`
}

// Option to pass to creator
type Option func(*HandlersTLS)

// WithEnvs to pass value as option
func WithEnvs(envs *environments.Environment) Option {
	return func(h *HandlersTLS) {
		h.Envs = envs
	}
}

// WithEnvsMap to pass value as option
func WithEnvsMap(envsmap *environments.MapEnvironments) Option {
	return func(h *HandlersTLS) {
		h.EnvsMap = envsmap
	}
}

// WithSettings to pass value as option
func WithSettings(settings *settings.Settings) Option {
	return func(h *HandlersTLS) {
		h.Settings = settings
	}
}

// WithSettingsMap to pass value as option
func WithSettingsMap(settingsmap *settings.MapSettings) Option {
	return func(h *HandlersTLS) {
		h.SettingsMap = settingsmap
	}
}

// WithNodes to pass value as option
func WithNodes(nodes *nodes.NodeManager) Option {
	return func(h *HandlersTLS) {
		h.Nodes = nodes
	}
}

// WithTags to pass value as option
func WithTags(tags *tags.TagManager) Option {
	return func(h *HandlersTLS) {
		h.Tags = tags
	}
}

// WithQueries to pass value as option
func WithQueries(queries *queries.Queries) Option {
	return func(h *HandlersTLS) {
		h.Queries = queries
	}
}

// WithCarves to pass value as option
func WithCarves(carves *carves.Carves) Option {
	return func(h *HandlersTLS) {
		h.Carves = carves
	}
}

// WithMetrics to pass value as option
func WithMetrics(metrics *metrics.Metrics) Option {
	return func(h *HandlersTLS) {
		h.Metrics = metrics
	}
}

// WithIngested to pass value as option
func WithIngested(ingested *metrics.IngestedManager) Option {
	return func(h *HandlersTLS) {
		h.Ingested = ingested
	}
}

// WithLogs to pass value as option
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
	envVar := r.PathValue("env")
	if envVar == "" {
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
	body, err := io.ReadAll(r.Body)
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
		newNode = nodeFromEnroll(t, env, utils.GetIP(r), nodeKey, len(body))
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
				if err := h.Tags.AutoTagNode(env.Name, newNode, "osctrl-tls"); err != nil {
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricConfigErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricConfigErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.ConfigRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricConfigErr)
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
		// Record ingested data
		if err := h.Ingested.IngestConfig(env.ID, node.ID, len(body)); err != nil {
			h.Inc(metricConfigErr)
			log.Printf("error with ingested config %v", err)
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricLogErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricLogErr)
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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricLogErr)
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
	node, err := h.Nodes.GetByKey(t.NodeKey)
	if err == nil {
		nodeInvalid = false
		// Record ingested data
		if err := h.Ingested.IngestLog(env.ID, node.ID, len(body), t.LogType); err != nil {
			h.Inc(metricLogErr)
			log.Printf("error with ingested log %v", err)
		}
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricReadErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricReadErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryReadRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricReadErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricReadErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid, accelerate bool
	qs := make(queries.QueryReadQueries)
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Record ingested data
		if err := h.Ingested.IngestQueryRead(env.ID, node.ID, len(body)); err != nil {
			h.Inc(metricReadErr)
			log.Printf("error with ingested query-read %v", err)
		}
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricReadErr)
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricWriteErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricWriteErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.QueryWriteRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricWriteErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricWriteErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	var nodeInvalid bool
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Record ingested data
		if err := h.Ingested.IngestQueryWrite(env.ID, node.ID, len(body)); err != nil {
			h.Inc(metricWriteErr)
			log.Printf("error with ingested query-write %v", err)
		}
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricWriteErr)
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
			h.Inc(metricWriteErr)
			log.Printf("error refreshing last query write %v", err)
		}
		// Process submitted results and mark query as processed
		go h.Logs.ProcessLogQueryResult(t, env.ID, (*h.EnvsMap)[env.Name].DebugHTTP)
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricOnelinerErr)
		log.Printf("error getting environment - %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Retrieve type of script
	script := r.PathValue("script")
	if script == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Script is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, settings.ScriptEnroll) {
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
	} else if strings.HasPrefix(script, settings.ScriptRemove) {
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
		log.Printf("error getting script - %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Error generating script"})
		return
	}
	// Send response
	utils.HTTPResponse(w, utils.TextPlainUTF8, http.StatusOK, []byte(quickScript))
	h.Inc(metricOnelinerOk)
}

// QuickRemoveHandler - Function to handle the endpoint for quick removal script
func (h *HandlersTLS) QuickRemoveHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricOnelinerReq)
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricOnelinerErr)
		log.Printf("error getting environment - %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Retrieve type of script
	script := r.PathValue("script")
	if script == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Script is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		h.Inc(metricOnelinerErr)
		log.Println("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, settings.ScriptEnroll) {
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
	} else if strings.HasPrefix(script, settings.ScriptRemove) {
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
		log.Printf("error getting script - %v", err)
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricInitErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricInitErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveInitRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricInitErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricInitErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	initCarve := false
	var carveSessionID string
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Record ingested data
		if err := h.Ingested.IngestCarveInit(env.ID, node.ID, len(body)); err != nil {
			h.Inc(metricInitErr)
			log.Printf("error with ingested carve-init %v", err)
		}
		ip := utils.GetIP(r)
		if err := h.Nodes.RecordIPAddress(ip, node); err != nil {
			h.Inc(metricInitErr)
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
			h.Inc(metricInitErr)
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
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricBlockErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.CarveBlockRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricBlockErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	blockCarve := false
	// Check if provided session_id matches with the request_id (carve query name)
	if carve, err := h.Carves.GetCheckCarve(t.SessionID, t.RequestID); err == nil {
		// Record ingested data
		if err := h.Ingested.IngestCarveBlock(env.ID, carve.NodeID, len(body)); err != nil {
			h.Inc(metricInitErr)
			log.Printf("error with ingested carve-block %v", err)
		}
		blockCarve = true
		// Process received block
		go h.ProcessCarveBlock(t, env.Name, carve.UUID, env.ID)
		// Refresh last carve request
		if err := h.Nodes.CarveRefreshByUUID(carve.UUID, utils.GetIP(r), len(body)); err != nil {
			h.Inc(metricBlockErr)
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

// FlagsHandler - Function to retrieve flags for osquery nodes, from osctrld
func (h *HandlersTLS) FlagsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricFlagsReq)
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricFlagsErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricFlagsErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.FlagsRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricFlagsErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricFlagsErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		flagsStr, err := h.Envs.GenerateFlags(env, t.SecrefFile, t.CertFile)
		if err != nil {
			h.Inc(metricFlagsErr)
			log.Printf("error generating flags %v", err)
			return
		}
		response = []byte(flagsStr)
	} else {
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Printf("Flags: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricFlagsOk)
}

// CertHandler - Function to retrieve certificate for osquery nodes, from osctrld
func (h *HandlersTLS) CertHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricCertReq)
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricCertErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricCertErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.CertRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricCertErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricCertErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		response = []byte(env.Certificate)
	} else {
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Printf("Certificate: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricCertOk)
}

// VerifyHandler - Function to verify status of enrolled osquery nodes, from osctrld
func (h *HandlersTLS) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricVerifyReq)
	var response types.VerifyResponse
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricVerifyErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricVerifyErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.VerifyRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricVerifyErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricVerifyErr)
		log.Printf("error parsing POST body %v", err)
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		flagsStr, err := h.Envs.GenerateFlags(env, t.SecrefFile, t.CertFile)
		if err != nil {
			h.Inc(metricVerifyErr)
			log.Printf("error generating flags %v", err)
			return
		}
		response = types.VerifyResponse{
			Certificate:    env.Certificate,
			Flags:          flagsStr,
			OsqueryVersion: defOsqueryVersion,
		}
	} else {
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte("uh oh..."))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Printf("Certificate: %v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricVerifyOk)
}

// ScriptHandler - Function to retrieve enroll/remove script for osquery nodes, from osctrld
func (h *HandlersTLS) ScriptHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricScriptReq)
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricScriptErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricScriptErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Retrieve and check action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		h.Inc(metricScriptErr)
		log.Println("Action is missing")
		return
	}
	if !validAction[actionVar] {
		h.Inc(metricScriptErr)
		log.Printf("invalid action: %s", actionVar)
		return
	}
	// Retrieve and check platform
	platformVar := r.PathValue("platform")
	if platformVar == "" {
		h.Inc(metricScriptErr)
		log.Println("Platform is missing")
		return
	}
	if !validPlatform[platformVar] {
		h.Inc(metricScriptErr)
		log.Printf("invalid platform: %s", platformVar)
		return
	}
	if platformVar == settings.PlatformDarwin || platformVar == settings.PlatformLinux {
		actionVar += environments.ShellTarget
	} else {
		actionVar += environments.PowershellTarget
	}
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Decode read POST body
	var t types.ScriptRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.Inc(metricScriptErr)
		log.Printf("error reading POST body %v", err)
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		h.Inc(metricScriptErr)
		log.Printf("error parsing POST body - %v", err)
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		script, err := environments.QuickAddScript("osctrl-"+env.Name, actionVar, env)
		if err != nil {
			h.Inc(metricScriptErr)
			log.Printf("error preparing script - %v", err)
			return
		}
		response = []byte(script)
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Printf("Script: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
	h.Inc(metricScriptOk)
}

// EnrollPackageHandler - Function to handle the endpoint for quick enrollment package download
func (h *HandlersTLS) EnrollPackageHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricPackageReq)
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricPackageErr)
		log.Println("Environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricPackageErr)
		log.Printf("error getting environment - %v", err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	utils.DebugHTTPDump(r, (*h.EnvsMap)[env.Name].DebugHTTP, true)
	// Retrieve package
	packageVar := r.PathValue("package")
	if packageVar == "" {
		h.Inc(metricPackageErr)
		log.Println("Package is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if requested package is valid
	if !validEnrollPackage[packageVar] {
		h.Inc(metricPackageErr)
		log.Printf("invalid package: %s", packageVar)
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		h.Inc(metricPackageErr)
		log.Println("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if !h.checkValidEnrollSecretPath(env, secretPath) {
		h.Inc(metricPackageErr)
		log.Println("Invalid secret path for enrolling package")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	if !h.checkExpiredEnrollSecretPath(env) {
		h.Inc(metricPackageErr)
		log.Println("Expired enrolling path for package")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
		return
	}
	// Prepare download
	var fDesc, fName, fPath string
	switch packageVar {
	case settings.PackageDeb:
		if strings.HasPrefix(env.DebPackage, "http") {
			http.Redirect(w, r, env.DebPackage, http.StatusFound)
			h.Inc(metricPackageOk)
			return
		}
		fDesc = "Enrolling DEB Package for Linux"
		fName = genPackageFilename(env.Name, settings.PackageDeb, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.DebPackage)
	case settings.PackageRpm:
		if strings.HasPrefix(env.RpmPackage, "http") {
			http.Redirect(w, r, env.RpmPackage, http.StatusFound)
			h.Inc(metricPackageOk)
			return
		}
		fDesc = "Enrolling RPM Package for Linux"
		fName = genPackageFilename(env.Name, settings.PackageRpm, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.RpmPackage)
	case settings.PackagePkg:
		if strings.HasPrefix(env.PkgPackage, "http") {
			http.Redirect(w, r, env.PkgPackage, http.StatusFound)
			h.Inc(metricPackageOk)
			return
		}
		fDesc = "Enrolling PKG Package for Mac"
		fName = genPackageFilename(env.Name, settings.PackagePkg, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.PkgPackage)
	case settings.PackageMsi:
		if strings.HasPrefix(env.MsiPackage, "http") {
			http.Redirect(w, r, env.MsiPackage, http.StatusFound)
			h.Inc(metricPackageOk)
			return
		}
		fDesc = "Enrolling MSI Package for Windows"
		fName = genPackageFilename(env.Name, settings.PackageMsi, defOsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.MsiPackage)
	}
	// Initiate download
	fi, err := os.Stat(fPath)
	if err != nil {
		h.Inc(metricPackageErr)
		log.Printf("Error loading file for package %s - %v", fPath, err)
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Package Error"})
		return
	}
	utils.HTTPDownload(w, fDesc, fName, fi.Size())
	w.WriteHeader(http.StatusOK)
	var fileReader io.Reader
	fileReader, _ = os.Open(fPath)
	_, err = io.Copy(w, fileReader)
	if err != nil {
		h.Inc(metricPackageErr)
		log.Printf("error copying file %v", err)
	}
	h.Inc(metricPackageOk)
}
