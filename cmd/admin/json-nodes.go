package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/javuto/osctrl/pkg/settings"
)

// Define targets to be used
var (
	NodeTargets = map[string]bool{
		"all":      true,
		"active":   true,
		"inactive": true,
	}
)

// ReturnedNodes to return a JSON with nodes
type ReturnedNodes struct {
	Data []NodeJSON `json:"data"`
}

// NodeJSON to be used to populate JSON data for a node
type NodeJSON struct {
	Checkbox  string        `json:"checkbox"`
	UUID      string        `json:"uuid"`
	Username  string        `json:"username"`
	Localname string        `json:"localname"`
	IP        string        `json:"ip"`
	Platform  string        `json:"platform"`
	Version   string        `json:"version"`
	Osquery   string        `json:"osquery"`
	LastSeen  CreationTimes `json:"lastseen"`
}

// Handler for JSON endpoints by environment
func jsonEnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract environment
	env, ok := vars["environment"]
	if !ok {
		log.Println("error getting environment")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Printf("invalid target %s", target)
		return
	}
	nodes, err := nodesmgr.GetByEnv(env, target)
	if err != nil {
		log.Printf("error getting nodes %v", err)
		return
	}
	// Prepare data to be returned
	nJSON := []NodeJSON{}
	for _, n := range nodes {
		nj := NodeJSON{
			UUID:      n.UUID,
			Username:  n.Username,
			Localname: n.Localname,
			IP:        n.IPAddress,
			Platform:  n.Platform,
			Version:   n.PlatformVersion,
			Osquery:   n.OsqueryVersion,
			LastSeen: CreationTimes{
				Display:   pastTimeAgo(n.UpdatedAt),
				Timestamp: pastTimestamp(n.UpdatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serialize JSON
	returnedJSON, err := json.Marshal(returned)
	if err != nil {
		log.Printf("error serializing JSON %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
}

// Handler for JSON endpoints by platform
func jsonPlatformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract platform
	platform, ok := vars["platform"]
	if !ok {
		log.Println("error getting platform")
		return
	}
	// Extract target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Verify target
	if !NodeTargets[target] {
		log.Printf("invalid target %s", target)
		return
	}
	nodes, err := nodesmgr.GetByPlatform(platform, target)
	if err != nil {
		log.Printf("error getting nodes %v", err)
		return
	}
	// Prepare data to be returned
	var nJSON []NodeJSON
	for _, n := range nodes {
		nj := NodeJSON{
			UUID:      n.UUID,
			Username:  n.Username,
			Localname: n.Localname,
			IP:        n.IPAddress,
			Platform:  n.Platform,
			Version:   n.PlatformVersion,
			Osquery:   n.OsqueryVersion,
			LastSeen: CreationTimes{
				Display:   pastTimeAgo(n.UpdatedAt),
				Timestamp: pastTimestamp(n.UpdatedAt),
			},
		}
		nJSON = append(nJSON, nj)
	}
	returned := ReturnedNodes{
		Data: nJSON,
	}
	// Serialize JSON
	returnedJSON, err := json.Marshal(returned)
	if err != nil {
		log.Printf("error serializing JSON %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
}
