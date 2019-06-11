package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/settings"
)

// Define targets to be used
var (
	StatsTargets = map[string]bool{
		"environment":  true,
		"platform": true,
	}
)

// Handler for platform/environment stats in JSON
func jsonStatsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract stats target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Verify target
	if !StatsTargets[target] {
		log.Printf("invalid target %s", target)
		return
	}
	// Extract stats name
	// FIXME verify name
	name, ok := vars["name"]
	if !ok {
		log.Println("error getting target name")
		return
	}
	// Get stats
	var stats nodes.StatsData
	var err error
	if target == "environment" {
		stats, err = nodesmgr.GetStatsByEnv(name)
		if err != nil {
			log.Printf("error getting stats %v", err)
			return
		}
	} else if target == "platform" {
		stats, err = nodesmgr.GetStatsByPlatform(name)
		if err != nil {
			log.Printf("error getting stats %v", err)
			return
		}
	}
	// Serialize JSON
	returnedJSON, err := json.Marshal(stats)
	if err != nil {
		log.Printf("error serializing JSON %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(returnedJSON)
}
