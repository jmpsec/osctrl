package main

import (
	"html/template"
	"log"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/unrolled/render"
)

// Handler for JSON endpoints by context
func jsonContextHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Check if context is valid
	if !contextExists(context) {
		log.Printf("error unknown context (%s)", context)
		return
	}
	// Extract target
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	nodes, err := getNodesByContext(context, target)
	if err != nil {
		log.Printf("error getting nodes %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"removeBackslash": removeBackslash,
		"pastTimeAgo":     pastTimeAgo,
	}
	// Fill template with data
	t, _ := template.New("nodes.tmpl").Funcs(funcMap).ParseFiles("tmpl_admin/json/nodes.tmpl")
	t.Execute(w, nodes)
}

// Handler for JSON endpoints by platform
func jsonPlatformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
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
	nodes, err := getNodesByPlatform(platform, target)
	if err != nil {
		log.Printf("error getting nodes %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"removeBackslash": removeBackslash,
		"pastTimeAgo":     pastTimeAgo,
	}
	// Fill template with data
	t, _ := template.New("nodes.tmpl").Funcs(funcMap).ParseFiles("tmpl_admin/json/nodes.tmpl")
	t.Execute(w, nodes)
}

// Handler for JSON queries by target
func jsonQueryHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract target
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Retrieve queries for that target
	queries, err := getQueries(target)
	if err != nil {
		log.Printf("error getting queries %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"removeBackslash":   removeBackslash,
		"pastTimeAgo":       pastTimeAgo,
		"resultsSearchLink": resultsSearchLink,
	}
	// Fill template with data
	var tmplName string
	switch target {
	case "active":
		tmplName = "active-queries.tmpl"
	case "completed":
		tmplName = "completed-queries.tmpl"
	}
	t, _ := template.New(tmplName).Funcs(funcMap).ParseFiles("tmpl_admin/json/" + tmplName)
	t.Execute(w, queries)
}

// Handler for node JSON
func jsonNodeHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		log.Println("error getting uuid")
		return
	}
	// Get node by UUID
	node, err := getNodeByUUID(uuid)
	if err != nil {
		log.Printf("error getting node %v", err)
		return
	}
	// Render and send node as JSON
	sender := render.New()
	sender.JSON(w, http.StatusOK, node)
}

// Handler GET requests for JSON status logs by node and context
func jsonStatusLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Extract UUID
	UUID, ok := vars["uuid"]
	if !ok {
		log.Println("error getting UUID")
		return
	}
	// Extract parameter for seconds
	secondsBack := int64(sixHours)
	seconds, ok := r.URL.Query()["seconds"]
	if ok {
		s, err := strconv.ParseInt(seconds[0], 10, 64)
		if err == nil {
			secondsBack = s
		}
	}
	// Get logs
	statusLogs, err := postgresStatusLogs(UUID, context, secondsBack)
	if err != nil {
		log.Printf("error getting logs %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimestamp": pastTimestamp,
		"stringEncode":  stringEncode,
		"pastTimeAgo":   pastTimeAgo,
	}
	// Fill template with data
	t := template.Must(template.New("status-logs.tmpl").Funcs(funcMap).ParseFiles("tmpl_admin/json/status-logs.tmpl"))
	t.Execute(w, statusLogs)
}

// Handler for JSON result logs by node and context
func jsonResultLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Extract UUID
	UUID, ok := vars["uuid"]
	if !ok {
		log.Println("error getting UUID")
		return
	}
	// Extract parameter for seconds
	secondsBack := int64(sixHours)
	seconds, ok := r.URL.Query()["seconds"]
	if ok {
		s, err := strconv.ParseInt(seconds[0], 10, 64)
		if err == nil {
			secondsBack = s
		}
	}
	resultLogs, err := postgresResultLogs(UUID, context, secondsBack)
	if err != nil {
		log.Printf("error getting logs %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimestamp": pastTimestamp,
		"stringEncode":  stringEncode,
		"pastTimeAgo":   pastTimeAgo,
	}
	// Fill template with data
	t := template.Must(template.New("result-logs.tmpl").Funcs(funcMap).ParseFiles("tmpl_admin/json/result-logs.tmpl"))
	t.Execute(w, resultLogs)
}

// Handler for JSON query logs by query name
func jsonQueryLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract query name
	name, ok := vars["name"]
	if !ok {
		log.Println("error getting context")
		return
	}
	queryLogs, err := postgresQueryLogs(name)
	if err != nil {
		log.Printf("error getting logs %v", err)
		return
	}
	// Header to serve JSON
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimestamp":         pastTimestamp,
		"stringEncode":          stringEncode,
		"removeBackslashEncode": removeBackslashEncode,
		"pastTimeAgo":           pastTimeAgo,
	}
	// Fill template with data
	t := template.Must(template.New("query-logs.tmpl").Funcs(funcMap).ParseFiles("tmpl_admin/json/query-logs.tmpl"))
	t.Execute(w, queryLogs)
}

// Handler for platform/context stats in JSON
func jsonStatsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract stats target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	var stats StatsData
	if target == "context" {
		contexts, err := getAllContexts()
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
		platforms, err := getAllPlatforms()
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
	t := template.Must(template.New("stats.tmpl").ParseFiles("tmpl_admin/json/stats.tmpl"))
	t.Execute(w, stats)
}
