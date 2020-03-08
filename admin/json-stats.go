package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/utils"
)

// Define targets to be used
var (
	StatsTargets = map[string]bool{
		"environment": true,
		"platform":    true,
	}
)

// Handler for platform/environment stats in JSON
func jsonStatsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract stats target
	target, ok := vars["target"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting target")
		return
	}
	// Verify target
	if !StatsTargets[target] {
		incMetric(metricAdminErr)
		log.Printf("invalid target %s", target)
		return
	}
	// Extract stats name
	// FIXME verify name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting target name")
		return
	}
	// Get stats
	var stats nodes.StatsData
	var err error
	if target == "environment" {
		stats, err = nodesmgr.GetStatsByEnv(name, settingsmgr.InactiveHours())
		if err != nil {
			incMetric(metricAdminErr)
			log.Printf("error getting stats %v", err)
			return
		}
	} else if target == "platform" {
		stats, err = nodesmgr.GetStatsByPlatform(name, settingsmgr.InactiveHours())
		if err != nil {
			log.Printf("error getting stats %v", err)
			return
		}
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, stats)
	incMetric(metricJSONOK)
}
