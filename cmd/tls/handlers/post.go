package handlers

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog/log"
)

// Per-endpoint request-body caps. Anonymous (pre-enroll) endpoints get a
// small cap; authenticated osquery endpoints get the headroom they need
// for legitimate workloads. Caps are an upper bound — handlers that
// previously read unbounded bodies now reject larger payloads with 413
// instead of letting the process OOM. (Tighten or relax via cfg later.)
const (
	maxBodyEnroll      = 64 * 1024         // 64 KiB — enroll request JSON
	maxBodyConfig      = 64 * 1024         // 64 KiB — config request JSON
	maxBodyLog         = 100 * 1024 * 1024 // 100 MiB — status/result log batch
	maxBodyQueryRead   = 16 * 1024         // 16 KiB — distributed-read request
	maxBodyQueryWrite  = 100 * 1024 * 1024 // 100 MiB — distributed-write result
	maxBodyCarveInit   = 8 * 1024          // 8 KiB — carve session init
	maxBodyCarveBlock  = 16 * 1024 * 1024  // 16 MiB — carve block (osquery carver_block_size default is 5 MiB)
	maxBodyQuickEnroll = 8 * 1024          // 8 KiB — quick-enroll
	maxBodyFlags       = 8 * 1024          // 8 KiB — flags request
	maxBodyCert        = 8 * 1024          // 8 KiB — cert request
	maxBodyVerify      = 8 * 1024          // 8 KiB — verify request
	maxBodyScript      = 8 * 1024          // 8 KiB — script request
	maxBodyOsqueryConf = 2 * 1024 * 1024   // 2 MiB — osctrld config push (base64+gzip; decompressed is capped at 500 KiB further down)
)

// readBody enforces the per-endpoint cap before reading the body. Wraps
// http.MaxBytesReader so the connection is closed cleanly on overflow
// rather than the handler streaming an arbitrarily large body.
func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	return io.ReadAll(r.Body)
}

// EnrollHandler - Function to handle the enroll requests from osquery nodes
func (h *HandlersTLS) EnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.EnvCache.GetByUUID(context.TODO(), envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if environment accept enrolls
	if !env.AcceptEnrolls {
		utils.HTTPResponse(w, "", http.StatusServiceUnavailable, []byte(""))
		return
	}
	// Debug HTTP for environment
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.EnrollRequest
	body, err := readBody(w, r, maxBodyEnroll)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
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
				log.Err(err).Msg("error archiving node")
			}
			// Update existing with new enroll data
			if err := h.Nodes.UpdateByUUID(newNode, t.HostIdentifier); err != nil {
				log.Err(err).Msg("error updating existing node")
			} else {
				nodeInvalid = false
			}
		} else { // New node, persist it
			if err := h.Nodes.Create(&newNode); err != nil {
				log.Err(err).Msg("error creating node")
			} else {
				nodeInvalid = false
				if err := h.Tags.AutoTagNode(env.Name, newNode, "osctrl-tls"); err != nil {
					log.Err(err).Msg("error tagging node")
				}
			}
		}
	} else {
		log.Err(err).Msg("invalid enrolling secret")
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	response := types.EnrollResponse{NodeKey: nodeKey, NodeInvalid: nodeInvalid}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// ConfigHandler - Function to handle the configuration requests from osquery nodes
func (h *HandlersTLS) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var response interface{}
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.EnvCache.GetByUUID(ctx, envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		return
	}
	// Debug HTTP for environment
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.ConfigRequest
	body, err := readBody(w, r, maxBodyConfig)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// We need to update the node info in another go routine
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Check if node belongs to the environment
		if node.EnvironmentID != env.ID {
			log.Warn().Msgf("node UUID: %s in %s environment does not belong to the environment", node.UUID, env.Name)
			response = types.ConfigResponse{NodeInvalid: true}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
			return
		}
		// Node and environment match, so we can proceed to update the node
		ip := utils.GetIP(r)
		if ip == node.IPAddress {
			ip = ""
		}
		h.WriteHandler.addEvent(lastSeenUpdate{NodeID: node.ID, IP: ip})
		log.Debug().Msgf("node-uuid: %s with nodeid %d added to batch writer for config update", node.UUID, node.ID)

		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "ConfigHandler").Observe(float64(len(body)))
		log.Debug().Msgf("node UUID: %s in %s environment ingested %d bytes for ConfigHandler endpoint", node.UUID, env.Name, len(body))
		response = []byte(env.Configuration)
	} else {
		response = types.ConfigResponse{NodeInvalid: true}
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		if x, ok := response.([]byte); ok {
			log.Debug().Msgf("Configuration: %s", string(x))
		} else {
			log.Debug().Msgf("Configuration: %+v", response)
		}
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// LogHandler - Function to handle the log requests from osquery nodes, both status and results
func (h *HandlersTLS) LogHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.EnvCache.GetByUUID(context.TODO(), envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if body is compressed, if so, uncompress
	if r.Header.Get("Content-Encoding") == "gzip" {
		r.Body, err = gzip.NewReader(r.Body)
		if err != nil {
			log.Err(err).Msg("error decoding gzip body")
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Err(err).Msg("Failed to close body")
				utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
				return
			}
		}()
	}
	// Debug HTTP here so the body will be uncompressed
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Extract POST body and decode JSON
	var t types.LogRequest
	body, err := readBody(w, r, maxBodyLog)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Err(err).Msg("Failed to close body")
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
	}()
	var nodeInvalid bool
	var response types.LogResponse
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Check if node belongs to the environment
		if node.EnvironmentID != env.ID {
			log.Warn().Msgf("node UUID: %s in %s environment does not belong to the environment", node.UUID, env.Name)
			response = types.LogResponse{NodeInvalid: true}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
			return
		}
		// Node and environment match, so we can proceed to update the node
		nodeInvalid = false
		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "LogHandler").Observe(float64(len(body)))
		log.Debug().Msgf("node UUID: %s in %s environment ingested %d bytes for LogHandler endpoint", node.UUID, env.Name, len(body))
		// Process logs and update metadata
		go func() {
			start := time.Now()
			h.Logs.ProcessLogs(t.Data, t.LogType, env.Name, utils.GetIP(r), len(body), (*h.EnvsMap)[env.Name].DebugHTTP)
			duration := time.Since(start).Seconds()
			logProcessDuration.WithLabelValues(string(env.UUID), t.LogType).Observe(duration)
		}()
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response = types.LogResponse{NodeInvalid: nodeInvalid}
	// Debug
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// QueryReadHandler - Function to handle on-demand queries to osquery nodes
func (h *HandlersTLS) QueryReadHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.EnvCache.GetByUUID(context.TODO(), envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.QueryReadRequest
	body, err := readBody(w, r, maxBodyQueryRead)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	var nodeInvalid, accelerate bool
	var response interface{}
	qs := make(queries.QueryReadQueries)
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Check if node belongs to the environment
		if node.EnvironmentID != env.ID {
			log.Warn().Msgf("node UUID: %s in %s environment does not belong to the environment", node.UUID, env.Name)
			response = types.ConfigResponse{NodeInvalid: true}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
			return
		}
		// Node and environment match, so we can proceed
		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "QueryRead").Observe(float64(len(body)))
		log.Debug().Msgf("node UUID: %s in %s environment ingested %d bytes for QueryReadHandler endpoint", node.UUID, env.Name, len(body))
		// Get queries and update node
		nodeInvalid = false
		qs, accelerate, err = h.Queries.NodeQueries(node)
		if err != nil {
			log.Err(err).Msg("error getting queries from db")
		}
		// Refresh node last seen
		ip := utils.GetIP(r)
		if ip == node.IPAddress {
			ip = ""
		}
		h.WriteHandler.addEvent(lastSeenUpdate{NodeID: node.ID, IP: ip})
		log.Debug().Msgf("node-uuid: %s with nodeid %d added to batch writer for query read update", node.UUID, node.ID)
	} else {
		log.Err(err).Msg("GetByKey")
		nodeInvalid = true
		accelerate = false
	}
	// Serialize queries
	if accelerate {
		sAccelerate := int((*h.SettingsMap)[settings.AcceleratedSeconds].Integer)
		response = types.AcceleratedQueryReadResponse{Queries: qs, Accelerate: sAccelerate, NodeInvalid: nodeInvalid}
	} else {
		response = types.QueryReadResponse{Queries: qs, NodeInvalid: nodeInvalid}
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Serialize and send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// QueryWriteHandler - Function to handle distributed query results from osquery nodes
func (h *HandlersTLS) QueryWriteHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.EnvCache.GetByUUID(context.TODO(), envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.QueryWriteRequest
	body, err := readBody(w, r, maxBodyQueryWrite)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	var nodeInvalid bool
	var response types.QueryWriteResponse
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Check if node belongs to the environment
		if node.EnvironmentID != env.ID {
			log.Warn().Msgf("node UUID: %s in %s environment does not belong to the environment", node.UUID, env.Name)
			response = types.QueryWriteResponse{NodeInvalid: true}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
			return
		}
		// Node and environment match, so we can proceed
		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "QueryWrite").Observe(float64(len(body)))
		log.Debug().Msgf("node UUID: %s in %s environment ingested %d bytes for QueryWriteHandler endpoint", node.UUID, env.Name, len(body))

		nodeInvalid = false
		for name, c := range t.Queries {
			var carves []types.QueryCarveScheduled
			if err := json.Unmarshal(c, &carves); err == nil {
				for _, cc := range carves {
					if cc.Carve == "1" {
						if err := h.ProcessCarveWrite(cc, name, t.NodeKey, env.Name); err != nil {
							log.Err(err).Msg("error scheduling carve")
						}
					}
				}
			}
		}
		// Refresh node last seen
		ip := utils.GetIP(r)
		if ip == node.IPAddress {
			ip = ""
		}
		h.WriteHandler.addEvent(lastSeenUpdate{NodeID: node.ID, IP: ip})
		// Process submitted results and mark query as processed
		go func() {
			start := time.Now()
			h.Logs.ProcessLogQueryResult(t, env.ID, (*h.EnvsMap)[env.Name].DebugHTTP)
			duration := time.Since(start).Seconds()
			distributedQueryProcessingDuration.WithLabelValues(string(env.UUID)).Observe(duration)
		}()
	} else {
		nodeInvalid = true
	}
	// Prepare response
	response = types.QueryWriteResponse{NodeInvalid: nodeInvalid}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// QuickEnrollHandler - Function to handle the endpoint for quick enrollment script distribution
func (h *HandlersTLS) QuickEnrollHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Retrieve type of script
	script := r.PathValue("script")
	if script == "" {
		log.Warn().Msg("Script is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		log.Warn().Msg("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, settings.ScriptEnroll) {
		if !h.checkValidEnrollSecretPath(env, secretPath) {
			log.Warn().Msg("Invalid secret path for enrolling")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredEnrollSecretPath(env) {
			log.Warn().Msg("Expired enrolling path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	} else if strings.HasPrefix(script, settings.ScriptRemove) {
		if !h.checkValidRemoveSecretPath(env, secretPath) {
			log.Warn().Msg("Invalid secret path for removing")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredRemoveSecretPath(env) {
			log.Warn().Msg("Expired removing path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript("osctrl-"+env.Name, script, env)
	if err != nil {
		log.Err(err).Msg("error getting script")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Error generating script"})
		return
	}
	// Send response
	utils.HTTPResponse(w, utils.TextPlainUTF8, http.StatusOK, []byte(quickScript))
}

// QuickRemoveHandler - Function to handle the endpoint for quick removal script
func (h *HandlersTLS) QuickRemoveHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Retrieve type of script
	script := r.PathValue("script")
	if script == "" {
		log.Warn().Msg("Script is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		log.Warn().Msg("Path is missing")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if strings.HasPrefix(script, settings.ScriptEnroll) {
		if !h.checkValidEnrollSecretPath(env, secretPath) {
			log.Debug().Msg("Invalid secret path for enrolling")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredEnrollSecretPath(env) {
			log.Debug().Msg("Expired enrolling path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	} else if strings.HasPrefix(script, settings.ScriptRemove) {
		if !h.checkValidRemoveSecretPath(env, secretPath) {
			log.Debug().Msg("Invalid secret path for removing")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Invalid"})
			return
		}
		if !h.checkExpiredRemoveSecretPath(env) {
			log.Debug().Msg("Expired removing path")
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Expired"})
			return
		}
	}
	// Prepare response with the script
	quickScript, err := environments.QuickAddScript("osctrl-"+env.Name, script, env)
	if err != nil {
		log.Err(err).Msg("error getting script")
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusInternalServerError, TLSResponse{Message: "Error generating script"})
		return
	}
	// Send response
	utils.HTTPResponse(w, utils.TextPlainUTF8, http.StatusOK, []byte(quickScript))
}

// CarveInitHandler - Function to handle the initialization of the file carver
// This function does not use go routines to handle requests because the session_id returned
// must be already created in the DB, otherwise block requests will fail.
func (h *HandlersTLS) CarveInitHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.CarveInitRequest
	body, err := readBody(w, r, maxBodyCarveInit)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	initCarve := false
	var carveSessionID string
	var response types.CarveInitResponse
	// Check if provided node_key is valid and if so, update node
	if node, err := h.Nodes.GetByKey(t.NodeKey); err == nil {
		// Check if node belongs to the environment
		if node.EnvironmentID != env.ID {
			log.Warn().Msgf("node UUID: %s in %s environment does not belong to the environment", node.UUID, env.Name)
			response = types.CarveInitResponse{Success: false, SessionID: ""}
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
			return
		}
		// Node and environment match, so we can proceed
		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "CarveInit").Observe(float64(len(body)))
		log.Debug().Msgf("node UUID: %s in %s environment ingested %d bytes for CarveInitHandler endpoint", node.UUID, env.Name, len(body))
		// Initialize carve
		initCarve = true
		carveSessionID = generateCarveSessionID()
		// Process carve init
		if err := h.ProcessCarveInit(t, carveSessionID, env.Name); err != nil {
			log.Err(err).Msg("error procesing carve init")
			initCarve = false
		}
		// Refresh last seen
		ip := utils.GetIP(r)
		if ip == node.IPAddress {
			ip = ""
		}
		h.WriteHandler.addEvent(lastSeenUpdate{NodeID: node.ID, IP: ip})
	}
	// Prepare response
	response = types.CarveInitResponse{Success: initCarve, SessionID: carveSessionID}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// CarveBlockHandler - Function to handle the blocks of the file carver
func (h *HandlersTLS) CarveBlockHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.CarveBlockRequest
	body, err := readBody(w, r, maxBodyCarveBlock)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	blockCarve := false
	// Check if provided session_id matches with the request_id (carve query name)
	if carve, err := h.Carves.GetCheckCarve(t.SessionID, t.RequestID); err == nil {
		// Record ingested data
		requestSize.WithLabelValues(string(env.UUID), "CarveBlock").Observe(float64(len(body)))
		log.Info().Msgf("node %d in %s environment ingested %d bytes for CarveBlockHandler endpoint", carve.NodeID, env.Name, len(body))
		blockCarve = true
		// Process received block
		go h.ProcessCarveBlock(t, env.Name, carve.UUID, env.ID)
		// Refresh last seen
		ip := utils.GetIP(r)
		h.WriteHandler.addEvent(lastSeenUpdate{NodeID: carve.NodeID, IP: ip})
	}
	// Prepare response
	response := types.CarveBlockResponse{Success: blockCarve}
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Response: %+v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// FlagsHandler - Function to retrieve flags for osquery nodes, from osctrld
func (h *HandlersTLS) FlagsHandler(w http.ResponseWriter, r *http.Request) {
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.FlagsRequest
	body, err := readBody(w, r, maxBodyFlags)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		flagsStr, err := h.Envs.GenerateFlags(env, t.SecrefFile, t.CertFile, *h.OsqueryValues)
		if err != nil {
			log.Err(err).Msg("error generating flags")
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
		response = []byte(flagsStr)
	} else {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Flags: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// CertHandler - Function to retrieve certificate for osquery nodes, from osctrld
func (h *HandlersTLS) CertHandler(w http.ResponseWriter, r *http.Request) {
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.CertRequest
	body, err := readBody(w, r, maxBodyCert)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		response = []byte(env.Certificate)
	} else {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte("uh oh..."))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Certificate: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// VerifyHandler - Function to verify status of enrolled osquery nodes, from osctrld
func (h *HandlersTLS) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	var response types.VerifyResponse
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.VerifyRequest
	body, err := readBody(w, r, maxBodyVerify)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		flagsStr, err := h.Envs.GenerateFlags(env, t.SecrefFile, t.CertFile, *h.OsqueryValues)
		if err != nil {
			log.Err(err).Msg("error generating flags")
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
		response = types.VerifyResponse{
			Certificate:    env.Certificate,
			Flags:          flagsStr,
			OsqueryVersion: defOsqueryVersion,
		}
	} else {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Certificate: %v", response)
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// ScriptHandler - Function to retrieve enroll/remove script for osquery nodes, from osctrld
func (h *HandlersTLS) ScriptHandler(w http.ResponseWriter, r *http.Request) {
	var response []byte
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Retrieve and check action
	actionVar := r.PathValue("action")
	if actionVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	if !validAction[actionVar] {
		log.Error().Msgf("invalid action: %s", actionVar)
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Retrieve and check platform
	platformVar := r.PathValue("platform")
	if platformVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	if !validPlatform[platformVar] {
		log.Error().Msgf("invalid platform: %s", platformVar)
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	if platformVar == settings.PlatformDarwin || platformVar == settings.PlatformLinux {
		actionVar += environments.ShellTarget
	} else {
		actionVar += environments.PowershellTarget
	}
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body
	var t types.ScriptRequest
	body, err := readBody(w, r, maxBodyScript)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &t); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Check if provided secret is valid and if so, prepare flags
	if h.checkValidSecret(t.Secret, env) {
		script, err := environments.QuickAddScript("osctrl-"+env.Name, actionVar, env)
		if err != nil {
			log.Err(err).Msg("error preparing script")
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
			return
		}
		response = []byte(script)
	} else {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	// Debug HTTP
	if (*h.EnvsMap)[env.Name].DebugHTTP {
		log.Debug().Msgf("Script: %s", string(response))
	}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}

// EnrollPackageHandler - Function to handle the endpoint for quick enrollment package download
func (h *HandlersTLS) EnrollPackageHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Get environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP if enabled
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Retrieve package
	packageVar := r.PathValue("package")
	if packageVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Check if requested package is valid
	if !validEnrollPackage[packageVar] {
		log.Error().Msgf("invalid package: %s", packageVar)
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Retrieve SecretPath variable
	secretPath := r.PathValue("secretpath")
	if secretPath == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Check if provided SecretPath is valid and is not expired
	if !h.checkValidEnrollSecretPath(env, secretPath) {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	if !h.checkExpiredEnrollSecretPath(env) {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	// Prepare download
	var fDesc, fName, fPath string
	switch packageVar {
	case settings.PackageDeb:
		if strings.HasPrefix(env.DebPackage, "http") {
			http.Redirect(w, r, env.DebPackage, http.StatusFound)
			return
		}
		fDesc = "Enrolling DEB Package for Linux"
		fName = genPackageFilename(env.Name, settings.PackageDeb, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.DebPackage)
	case settings.PackageRpm:
		if strings.HasPrefix(env.RpmPackage, "http") {
			http.Redirect(w, r, env.RpmPackage, http.StatusFound)
			return
		}
		fDesc = "Enrolling RPM Package for Linux"
		fName = genPackageFilename(env.Name, settings.PackageRpm, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.RpmPackage)
	case settings.PackagePkg:
		if strings.HasPrefix(env.PkgPackage, "http") {
			http.Redirect(w, r, env.PkgPackage, http.StatusFound)
			return
		}
		fDesc = "Enrolling PKG Package for Mac"
		fName = genPackageFilename(env.Name, settings.PackagePkg, version.OsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.PkgPackage)
	case settings.PackageMsi:
		if strings.HasPrefix(env.MsiPackage, "http") {
			http.Redirect(w, r, env.MsiPackage, http.StatusFound)
			return
		}
		fDesc = "Enrolling MSI Package for Windows"
		fName = genPackageFilename(env.Name, settings.PackageMsi, defOsqueryVersion, version.OsctrlVersion)
		fPath = fmt.Sprintf("%s/%s/%s", enrollPackagesPath, env.Name, env.MsiPackage)
	}
	// Initiate download
	fi, err := os.Stat(fPath)
	if err != nil {
		log.Err(err).Msgf("Error loading file for package %s", fPath)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	utils.HTTPDownload(w, fDesc, fName, fi.Size())
	w.WriteHeader(http.StatusOK)
	var fileReader io.Reader
	fileReader, _ = os.Open(fPath)
	_, err = io.Copy(w, fileReader)
	if err != nil {
		log.Err(err).Msg("error copying file")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
}

// OsqueryConfigEndpointHandler - Function to handle the osquery configuration endpoint
func (h *HandlersTLS) OsqueryConfigEndpointHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve environment variable
	envVar := r.PathValue("env")
	if envVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// To prevent abuse, check if the received UUID is valid
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	// Extract secret
	secretVar := r.PathValue("secret")
	if secretVar == "" {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	confirmed := false
	integrityCheck := false
	for _, confEndpoint := range *h.ConfigEndpoints {
		if confEndpoint.Environment == envVar && confEndpoint.Secret == secretVar {
			confirmed = true
			integrityCheck = confEndpoint.IntegrityCheck
			break
		}
	}
	if !confirmed {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return
	}
	// If we are here, the secret is confirmed, so we can proceed to get the environment
	env, err := h.Envs.GetByUUID(envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Debug HTTP
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	// Decode read POST body. Even though we cap the *decompressed*
	// configuration at 500 KiB below, the raw POST body also needs a cap —
	// otherwise an authenticated client (post-secret-check) can send an
	// arbitrarily large body and OOM the process. 2 MiB leaves ample
	// headroom for base64+gzip framing around a 500 KiB config.
	var o types.OsqueryConfigRequest
	body, err := readBody(w, r, maxBodyOsqueryConf)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if err := json.Unmarshal(body, &o); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Decode base64 configuration
	configDecoded, err := base64.StdEncoding.DecodeString(o.Configuration)
	if err != nil {
		log.Err(err).Msg("error decoding base64 configuration")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Unzip configuration
	gzipReader, err := gzip.NewReader(bytes.NewReader(configDecoded))
	if err != nil {
		log.Err(err).Msg("error decoding gzip configuration")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	defer gzipReader.Close()
	const maxConfigSize = 500 * 1024
	limitedReader := io.LimitReader(gzipReader, maxConfigSize+1)
	configuration, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Err(err).Msg("error reading unzipped configuration")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if len(configuration) > maxConfigSize {
		log.Error().Msg("unzipped configuration is larger than 500KB")
		utils.HTTPResponse(w, "", http.StatusRequestEntityTooLarge, []byte(""))
		return
	}
	// Verify integrity of the configuration using the provided hash
	if integrityCheck {
		hash := sha256.Sum256(configuration)
		computedIntegrity := fmt.Sprintf("%x", hash)
		if o.Integrity != computedIntegrity {
			log.Warn().
				Str("expected_integrity", o.Integrity).
				Str("computed_integrity", computedIntegrity).
				Msg("configuration integrity check failed")
			utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
			return
		}
	}
	// Parse configuration
	cnf, err := h.Envs.GenStructConf(configuration)
	if err != nil {
		log.Err(err).Msg("error parsing configuration")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Update full configuration
	if err := h.Envs.UpdateConfiguration(env.UUID, cnf); err != nil {
		log.Err(err).Msg("error saving configuration")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	// Update all configuration parts
	if err := h.Envs.UpdateConfigurationParts(env.UUID, cnf); err != nil {
		log.Err(err).Msg("error saving configuration parts")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	response := TLSResponse{Message: "configuration saved successfully"}
	// Send response
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, response)
}
