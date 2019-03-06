package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/javuto/osctrl/nodes"
)

// Define targets to be used
var (
	NodeTargets = map[string]bool{
		"all":       true,
		"active":    true,
		"completed": true,
	}
)

// ReturnedNodes to return a JSON with nodes
type ReturnedNodes struct {
	Data []NodeJSON `json:"data"`
}

// NodeJSON to be used to populate JSON data for a node
type NodeJSON struct {
	Checkbox  string `json:"checkbox"`
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	Localname string `json:"localname"`
	IP        string `json:"ip"`
	Platform  string `json:"platform"`
	Version   string `json:"version"`
	Osquery   string `json:"osquery"`
	LastSeen  string `json:"lastseen"`
}

// Handler for JSON endpoints by context
func jsonContextHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	vars := mux.Vars(r)
	// Extract context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(context) {
		log.Printf("error unknown context (%s)", context)
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
	nodes, err := nodesmgr.GetByContext(context, target)
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
			LastSeen:  pastTimeAgo(n.UpdatedAt),
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
	w.Write(returnedJSON)
}

// Handler for JSON endpoints by platform
func jsonPlatformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
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
			LastSeen:  pastTimeAgo(n.UpdatedAt),
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
	w.Write(returnedJSON)
}

// Handler for platform/context stats in JSON
func jsonStatsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	vars := mux.Vars(r)
	// Extract stats target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	var stats nodes.StatsData
	if target == "context" {
		contexts, err := ctxs.All()
		if err != nil {
			log.Printf("error getting contexts: %v", err)
			return
		}
		stats, err = getContextStats(contexts)
		if err != nil {
			log.Printf("error getting context stats: %v", err)
			return
		}
	}
	if target == "platform" {
		platforms, err := nodesmgr.GetAllPlatforms()
		if err != nil {
			log.Printf("error getting platforms: %v", err)
			return
		}
		stats, err = getPlatformStats(platforms)
		if err != nil {
			log.Printf("error getting platform stats: %v", err)
			return
		}
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Prepare and fill template with data
	t := template.Must(template.New("stats.tmpl").ParseFiles(
		"tmpl_admin/json/stats.tmpl"))
	t.Execute(w, stats)
}
