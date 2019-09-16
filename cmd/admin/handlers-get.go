package main

import (
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/utils"

	"github.com/gorilla/mux"
)

const (
	templatesFilesFolder string = "tmpl_admin"
)

// Handler for login page for GET requests
func loginGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/login.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting login template: %v", err)
		return
	}
	// Prepare template data
	templateData := LoginTemplateData{
		Title:   "Login to " + projectName,
		Project: projectName,
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login template served")
	}
	incMetric(metricAdminOK)
}

// Handler for the root path
func rootHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Redirect to table for active nodes in default environment
	defaultEnvironment := settingsmgr.DefaultEnv(settings.ServiceAdmin)
	if envs.Exists(defaultEnvironment) {
		http.Redirect(w, r, "/environment/"+defaultEnvironment+"/active", http.StatusFound)
	} else {
		http.Redirect(w, r, "/environments", http.StatusFound)
	}
}

// Handler for environment view of the table
func environmentHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract environment
	env, ok := vars["environment"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting environment")
		return
	}
	// Check if environment is valid
	if !envs.Exists(env) {
		incMetric(metricAdminErr)
		log.Printf("error unknown environment (%s)", env)
		return
	}
	// Extract target
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting target")
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/table.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := TableTemplateData{
		Title:          "Nodes in " + env,
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Selector:       "environment",
		SelectorName:   env,
		Target:         target,
		Environments:   envAll,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Environment table template served")
	}
	incMetric(metricAdminOK)
}

// Handler for platform view of the table
func platformHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract platform
	// FIXME verify platform
	platform, ok := vars["platform"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting platform")
		return
	}
	// Extract target
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting target")
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/table.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := TableTemplateData{
		Title:          "Nodes in " + platform,
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Selector:       "platform",
		SelectorName:   platform,
		Target:         target,
		Environments:   envAll,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Platform table template served")
	}
	incMetric(metricAdminOK)
}

// Handler for GET requests to run queries
func queryRunGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/queries-run.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get all nodes
	nodes, err := nodesmgr.Gets("active", settingsmgr.InactiveHours())
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting all nodes: %v", err)
		return
	}
	// Convert to list of UUIDs and Hosts
	// FIXME if the number of nodes is big, this may cause issues loading the page
	var uuids, hosts []string
	for _, n := range nodes {
		uuids = append(uuids, n.UUID)
		hosts = append(hosts, n.Localname)
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := QueryRunTemplateData{
		Title:          "Query osquery Nodes",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		UUIDs:          uuids,
		Hosts:          hosts,
		Tables:         osqueryTables,
		TablesVersion:  osqueryTablesVersion,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run template served")
	}
	incMetric(metricAdminOK)
}

// Handler for GET requests to queries
func queryListGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/queries.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := QueryTableTemplateData{
		Title:          "All on-demand queries",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		Target:         "all",
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query list template served")
	}
	incMetric(metricAdminOK)
}

// Handler for GET requests to run file carves
func carvesRunGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/carves-run.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get all nodes
	nodes, err := nodesmgr.Gets("active", settingsmgr.InactiveHours())
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting all nodes: %v", err)
		return
	}
	// Convert to list of UUIDs and Hosts
	// FIXME if the number of nodes is big, this may cause issues loading the page
	var uuids, hosts []string
	for _, n := range nodes {
		uuids = append(uuids, n.UUID)
		hosts = append(hosts, n.Localname)
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := CarvesRunTemplateData{
		Title:          "Query osquery Nodes",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		UUIDs:          uuids,
		Hosts:          hosts,
		Tables:         osqueryTables,
		TablesVersion:  osqueryTablesVersion,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run template served")
	}
	incMetric(metricAdminOK)
}

// Handler for GET requests to carves
func carvesListGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/carves.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := CarvesTableTemplateData{
		Title:          "All carved files",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		Target:         "all",
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve list template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests to see query results by name
func queryLogsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting name")
		return
	}
	// Prepare template
	t, err := template.New("queries-logs.html").ParseFiles(
		templatesFilesFolder + "/queries-logs.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting query %v", err)
		return
	}
	// Get query targets
	targets, err := queriesmgr.GetTargets(name)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting targets %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := QueryLogsTemplateData{
		Title:          "Query logs " + query.Name,
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		Query:          query,
		QueryTargets:   targets,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query logs template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests to see carves details by name
func carvesDetailsHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting name")
		return
	}
	// Prepare template
	t, err := template.New("carves-details.html").ParseFiles(
		templatesFilesFolder + "/carves-details.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}

	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting query %v", err)
		return
	}
	// Get query targets
	targets, err := queriesmgr.GetTargets(name)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting targets %v", err)
		return
	}
	// Get carves for this query
	queryCarves, err := carvesmgr.GetByQuery(name)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting carve %v", err)
		return
	}
	// Get carve blocks by carve
	blocks := make(map[string][]carves.CarvedBlock)
	for _, c := range queryCarves {
		bs, err := carvesmgr.GetBlocks(c.SessionID)
		if err != nil {
			incMetric(metricAdminErr)
			log.Printf("error getting carve blocks %v", err)
			break
		}
		blocks[c.SessionID] = bs
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := CarvesDetailsTemplateData{
		Title:          "Carve details " + query.Name,
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		Query:          query,
		QueryTargets:   targets,
		Carves:         queryCarves,
		CarveBlocks:    blocks,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve details template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests for /conf
func confGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(envVar) {
		incMetric(metricAdminErr)
		log.Printf("error unknown environment (%s)", envVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/conf.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-modals.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting conf template: %v", err)
		return
	}
	// Get stats for all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get configuration JSON
	env, err := envs.Get(envVar)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := ConfTemplateData{
		Title:          envVar + " Configuration",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environment:    env,
		Environments:   envAll,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Conf template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests for /enroll
func enrollGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract environment
	envVar, ok := vars["environment"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("environment is missing")
		return
	}
	// Check if environment is valid
	if !envs.Exists(envVar) {
		incMetric(metricAdminErr)
		log.Printf("error unknown environment (%s)", envVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/enroll.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting enroll template: %v", err)
		return
	}
	// Get stats for all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get configuration JSON
	env, err := envs.Get(envVar)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environment %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	shellQuickAdd, _ := environments.QuickAddOneLinerShell(env)
	powershellQuickAdd, _ := environments.QuickAddOneLinerPowershell(env)
	shellQuickRemove, _ := environments.QuickRemoveOneLinerShell(env)
	powershellQuickRemove, _ := environments.QuickRemoveOneLinerPowershell(env)
	templateData := EnrollTemplateData{
		Title:                 envVar + " Enroll",
		Username:              ctx["user"],
		CSRFToken:             ctx["csrftoken"],
		EnvName:               envVar,
		EnrollExpiry:          strings.ToUpper(inFutureTime(env.EnrollExpire)),
		EnrollExpired:         environments.IsItExpired(env.EnrollExpire),
		RemoveExpiry:          strings.ToUpper(inFutureTime(env.RemoveExpire)),
		RemoveExpired:         environments.IsItExpired(env.RemoveExpire),
		QuickAddShell:         shellQuickAdd,
		QuickRemoveShell:      shellQuickRemove,
		QuickAddPowershell:    powershellQuickAdd,
		QuickRemovePowershell: powershellQuickRemove,
		Secret:                env.Secret,
		Flags:                 env.Flags,
		Certificate:           env.Certificate,
		Environments:          envAll,
		Platforms:             platforms,
		TLSDebug:              settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:            settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP:        settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Enroll template served")
	}
	incMetric(metricAdminOK)
}

// Handler for node view
func nodeHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting uuid")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimeAgo":   pastTimeAgo,
		"jsonRawIndent": jsonRawIndent,
		"statusLogsLink": statusLogsLink,
		"resultLogsLink": resultLogsLink,
	}
	// Prepare template
	t, err := template.New("node.html").Funcs(funcMap).ParseFiles(
		templatesFilesFolder + "/node.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments%v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get node by UUID
	node, err := nodesmgr.GetByUUID(uuid)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting node %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := NodeTemplateData{
		Title:          "Node View " + node.Hostname,
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Logs:           adminConfig.Logging,
		Node:           node,
		Environments:   envAll,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Node template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests for /env
func envsGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/environments.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments template: %v", err)
		return
	}
	// Get stats for all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := EnvironmentsTemplateData{
		Title:          "Manage environments",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Environments template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests for /settings
func settingsGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting service")
		return
	}
	// Verify service
	if serviceVar != settings.ServiceTLS && serviceVar != settings.ServiceAdmin {
		incMetric(metricAdminErr)
		log.Printf("error unknown service (%s)", serviceVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		templatesFilesFolder + "/settings.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments template: %v", err)
		return
	}
	// Get stats for all environments
	envAll, err := envs.All()
	if err != nil {
		log.Printf("error getting environments %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get setting values
	_settings, err := settingsmgr.RetrieveValues(serviceVar)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting settings: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Get JSON values
	svcJSON, err := settingsmgr.RetrieveAllJSON(serviceVar)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting JSON values: %v", err)
	}
	// Prepare template data
	templateData := SettingsTemplateData{
		Title:           "Manage settings",
		Username:        ctx["user"],
		CSRFToken:       ctx["csrftoken"],
		Service:         serviceVar,
		Environments:    envAll,
		Platforms:       platforms,
		CurrentSettings: _settings,
		ServiceConfig:   toJSONConfigurationService(svcJSON),
		TLSDebug:        settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:      settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP:  settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Settings template served")
	}
	incMetric(metricAdminOK)
}

// Handler GET requests for /users
func usersGETHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimeAgo": pastTimeAgo,
	}
	// Prepare template
	t, err := template.New("users.html").Funcs(funcMap).ParseFiles(
		templatesFilesFolder + "/users.html",
		templatesFilesFolder + "/components/page-head.html",
		templatesFilesFolder + "/components/page-js.html",
		templatesFilesFolder + "/components/page-header.html",
		templatesFilesFolder + "/components/page-sidebar.html",
		templatesFilesFolder + "/components/page-aside.html",
		templatesFilesFolder + "/components/page-modals.html")
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments template: %v", err)
		return
	}
	// Get stats for all environments
	envAll, err := envs.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting environments %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get current users
	users, err := adminUsers.All()
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error getting users: %v", err)
		return
	}
	// Get context data
	ctx := r.Context().Value(contextKey("session")).(contextValue)
	// Prepare template data
	templateData := UsersTemplateData{
		Title:          "Manage users",
		Username:       ctx["user"],
		CSRFToken:      ctx["csrftoken"],
		Environments:   envAll,
		Platforms:      platforms,
		CurrentUsers:   users,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		incMetric(metricAdminErr)
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users template served")
	}
	incMetric(metricAdminOK)
}

// Handler for GET requests to download carves
func carvesDownloadHandler(w http.ResponseWriter, r *http.Request) {
	incMetric(metricAdminReq)
	utils.DebugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract id to download
	carveSession, ok := vars["sessionid"]
	if !ok {
		incMetric(metricAdminErr)
		log.Println("error getting carve")
		return
	}
	// Prepare file to download
	result, err := carvesmgr.Archive(carveSession, carvedFilesFolder)
	if err != nil {
		incMetric(metricAdminErr)
		log.Printf("error downloading carve - %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve download")
	}
	incMetric(metricAdminOK)
	// Send response
	w.Header().Set("Content-Description", "File Carve Download")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+result.File)
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Connection", "Keep-Alive")
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "public")
	w.Header().Set("Content-Length", strconv.FormatInt(result.Size, 10))
	w.WriteHeader(http.StatusOK)
	var fileReader io.Reader
	fileReader, _ = os.Open(result.File)
	_, _ = io.Copy(w, fileReader)
}
