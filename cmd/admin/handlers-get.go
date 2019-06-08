package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/javuto/osctrl/pkg/context"
	"github.com/javuto/osctrl/pkg/settings"

	"github.com/gorilla/mux"
)

// Handler for login page for GET requests
func loginGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/login.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html")
	if err != nil {
		log.Printf("error getting login template: %v", err)
		return
	}
	// Prepare template data
	templateData := LoginTemplateData{
		Title:   "Login to " + projectName,
		Project: projectName,
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Login template served")
	}
}

// Handler for the root path
func rootHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Redirect to table for active nodes in default context
	defaultContext := settingsmgr.DefaultContext(settings.ServiceAdmin)
	if ctxs.Exists(defaultContext) {
		http.Redirect(w, r, "/context/"+defaultContext+"/active", http.StatusFound)
	} else {
		http.Redirect(w, r, "/context/dev/active", http.StatusFound)
	}
}

// Handler for context view of the table
func contextHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
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
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/table.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:          "Nodes in " + context + " Context",
		Selector:       "context",
		SelectorName:   context,
		Target:         target,
		Contexts:       contexts,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Context table template served")
	}
}

// Handler for platform view of the table
func platformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract platform
	// FIXME verify platform
	platform, ok := vars["platform"]
	if !ok {
		log.Println("error getting platform")
		return
	}
	// Extract target
	// FIXME verify target
	target, ok := vars["target"]
	if !ok {
		log.Println("error getting target")
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/table.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:          "Nodes in " + platform + " Platform",
		Selector:       "platform",
		SelectorName:   platform,
		Target:         target,
		Contexts:       contexts,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Platform table template served")
	}
}

// Handler for GET requests to run queries
func queryRunGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/query-run.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get all nodes
	nodes, err := nodesmgr.Gets("active")
	if err != nil {
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
	// Prepare template data
	templateData := QueryRunTemplateData{
		Title:          "Query osquery Nodes",
		Contexts:       contexts,
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
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query run template served")
	}
}

// Handler for GET requests to queries
func queryListGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/queries.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get queries
	qs, err := queriesmgr.Gets("all")
	if err != nil {
		log.Printf("error getting active queries: %v", err)
		return
	}
	// Prepare template data
	templateData := QueryTableTemplateData{
		Title:          "All on-demand queries",
		Contexts:       contexts,
		Platforms:      platforms,
		Queries:        qs,
		Target:         "all",
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query list template served")
	}
}

// Handler GET requests to see query results by name
func queryLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		log.Println("error getting name")
		return
	}
	// Prepare template
	t, err := template.New("query-logs.html").ParseFiles(
		"tmpl_admin/query-logs.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}

	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get query by name
	query, err := queriesmgr.Get(name)
	if err != nil {
		log.Printf("error getting query %v", err)
		return
	}
	// Get query targets
	targets, err := queriesmgr.GetTargets(name)
	if err != nil {
		log.Printf("error getting targets %v", err)
		return
	}
	// Prepare template data
	templateData := QueryLogsTemplateData{
		Title:          "Query logs " + query.Name,
		Contexts:       contexts,
		Platforms:      platforms,
		Query:          query,
		QueryTargets:   targets,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Query logs template served")
	}
}

// Handler GET requests for /conf
func confGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract context
	contextVar, ok := vars["context"]
	if !ok {
		log.Println("context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(contextVar) {
		log.Printf("error unknown context (%s)", contextVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/conf.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-modals.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html")
	if err != nil {
		log.Printf("error getting conf template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get configuration JSON
	ctx, err := ctxs.Get(contextVar)
	if err != nil {
		log.Printf("error getting context %v", err)
		return
	}
	// Prepare template data
	templateData := ConfTemplateData{
		Title:          contextVar + " Configuration",
		Context:        ctx,
		Contexts:       contexts,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Conf template served")
	}
}

// Handler GET requests for /enroll
func enrollGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract context
	contextVar, ok := vars["context"]
	if !ok {
		log.Println("context is missing")
		return
	}
	// Check if context is valid
	if !ctxs.Exists(contextVar) {
		log.Printf("error unknown context (%s)", contextVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/enroll.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting enroll template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get configuration JSON
	ctx, err := ctxs.Get(contextVar)
	if err != nil {
		log.Printf("error getting context %v", err)
		return
	}
	// Prepare template data
	shellQuickAdd, _ := context.QuickAddOneLinerShell(ctx)
	powershellQuickAdd, _ := context.QuickAddOneLinerPowershell(ctx)
	shellQuickRemove, _ := context.QuickRemoveOneLinerShell(ctx)
	powershellQuickRemove, _ := context.QuickRemoveOneLinerPowershell(ctx)
	templateData := EnrollTemplateData{
		Title:                 contextVar + " Enroll",
		Context:               contextVar,
		EnrollExpiry:          strings.ToUpper(inFutureTime(ctx.EnrollExpire)),
		EnrollExpired:         context.IsItExpired(ctx.EnrollExpire),
		RemoveExpiry:          strings.ToUpper(inFutureTime(ctx.RemoveExpire)),
		RemoveExpired:         context.IsItExpired(ctx.RemoveExpire),
		QuickAddShell:         shellQuickAdd,
		QuickRemoveShell:      shellQuickRemove,
		QuickAddPowershell:    powershellQuickAdd,
		QuickRemovePowershell: powershellQuickRemove,
		Contexts:              contexts,
		Platforms:             platforms,
		TLSDebug:              settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:            settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP:        settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Enroll template served")
	}
}

// Handler for node view
func nodeHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		log.Println("error getting uuid")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimeAgo": pastTimeAgo,
	}
	// Prepare template
	t, err := template.New("node.html").Funcs(funcMap).ParseFiles(
		"tmpl_admin/node.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts%v", err)
		return
	}
	// Get all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get node by UUID
	node, err := nodesmgr.GetByUUID(uuid)
	if err != nil {
		log.Printf("error getting node %v", err)
		return
	}
	// Prepare template data
	templateData := NodeTemplateData{
		Title:          "Node View " + node.UUID,
		PostgresLogs:   logConfig.Postgres,
		Node:           node,
		Contexts:       contexts,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Node template served")
	}
}

// Handler GET requests for /contexts
func contextsGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/contexts.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting contexts template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Prepare template data
	templateData := ContextsTemplateData{
		Title:          "Manage contexts",
		Contexts:       contexts,
		Platforms:      platforms,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Contexts template served")
	}
}

// Handler GET requests for /settings
func settingsGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		log.Println("error getting service")
		return
	}
	// Verify service
	if serviceVar != settings.ServiceTLS && serviceVar != settings.ServiceAdmin {
		log.Printf("error unknown service (%s)", serviceVar)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/settings.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting contexts template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get setting values
	_settings, err := settingsmgr.RetrieveValues(serviceVar)
	if err != nil {
		log.Printf("error getting settings: %v", err)
		return
	}
	// Prepare template data
	templateData := SettingsTemplateData{
		Title:           "Manage settings",
		Service:         serviceVar,
		Contexts:        contexts,
		Platforms:       platforms,
		CurrentSettings: _settings,
		TLSDebug:        settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:      settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP:  settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Settings template served")
	}
}

// Handler GET requests for /users
func usersGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(settings.ServiceAdmin), false)
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastTimeAgo": pastTimeAgo,
	}
	// Prepare template
	t, err := template.New("users.html").Funcs(funcMap).ParseFiles(
		"tmpl_admin/users.html",
		"tmpl_admin/components/page-head.html",
		"tmpl_admin/components/page-js.html",
		"tmpl_admin/components/page-header.html",
		"tmpl_admin/components/page-sidebar.html",
		"tmpl_admin/components/page-aside.html",
		"tmpl_admin/components/page-modals.html")
	if err != nil {
		log.Printf("error getting contexts template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := ctxs.All()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := nodesmgr.GetAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	// Get current users
	users, err := usersmgr.All()
	if err != nil {
		log.Printf("error getting users: %v", err)
		return
	}
	// Prepare template data
	templateData := UsersTemplateData{
		Title:          "Manage users",
		Contexts:       contexts,
		Platforms:      platforms,
		CurrentUsers:   users,
		TLSDebug:       settingsmgr.DebugService(settings.ServiceTLS),
		AdminDebug:     settingsmgr.DebugService(settings.ServiceAdmin),
		AdminDebugHTTP: settingsmgr.DebugHTTP(settings.ServiceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Users template served")
	}
}
