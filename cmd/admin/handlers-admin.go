package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// TextPlain for Content-Type headers
const TextPlain string = "text/plain"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// TextPlainUTF8 for Content-Type headers, UTF charset
const TextPlainUTF8 string = TextPlain + "; charset=UTF-8"

// Handler to serve static content with the proper header
func staticHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)

	path := r.URL.Path
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	} else if strings.HasSuffix(path, ".eot") {
		w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
	} else if strings.HasSuffix(path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	} else if strings.HasSuffix(path, ".ttf") {
		w.Header().Set("Content-Type", "application/x-font-ttf")
	} else if strings.HasSuffix(path, ".woff") {
		w.Header().Set("Content-Type", "application/font-woff")
	} else if strings.HasSuffix(path, ".woff2") {
		w.Header().Set("Content-Type", "application/font-woff2")
	} else if strings.HasSuffix(path, ".otf") {
		w.Header().Set("Content-Type", "application/x-font-otf")
	} else if strings.HasSuffix(path, ".ico") {
		w.Header().Set("Content-Type", "image/x-icon")
	} else if strings.HasSuffix(path, ".gif") {
		w.Header().Set("Content-Type", "image/gif")
	} else if strings.HasSuffix(path, ".png") {
		w.Header().Set("Content-Type", "image/png")
	}

	http.ServeFile(w, r, path)
}

// Handler for the favicon
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)

	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, "./static/favicon.png")
}

// Handler for login page for GET requests
func loginGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/login.html",
		"tmpl_admin/head.html")
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
}

// Handler for login page for POST requests
func loginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	responseMessage := "OK"
	responseCode := http.StatusOK
	var l LoginRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
	// Check credentials
	if access, user := checkLoginCredentials(l.Username, l.Password); access {
		session, err := store.Get(r, projectName)
		if err != nil {
			log.Printf("New session - %v", err)
		}
		session.Values["authenticated"] = true
		session.Values["user"] = l.Username
		session.Values["admin"] = user.Admin
		session.Values["csrftoken"] = generateCSRF()
		session.Save(r, w)
	} else {
		responseMessage = "invalid credentials"
		responseCode = http.StatusForbidden
		log.Printf("%s %v", responseMessage, err)
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handle POST requests to logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	var l LogoutRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
	// Check CSRF Token
	if checkCSRFToken(l.CSRFToken) {
		// Access existing session
		session, err := store.Get(r, projectName)
		if err != nil {
			log.Printf("error accessing session [ %v ]", err)
			http.Error(w, "Session Error", http.StatusInternalServerError)
			return
		}
		// Revoke users authentication
		session.Values["authenticated"] = false
		session.Values["user"] = ""
		session.Save(r, w)
	} else {
		responseMessage = "invalid CSRF token"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for the root path
func rootHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	// Redirect to table for all nodes
	if contextExists("corp") {
		http.Redirect(w, r, "/context/corp/all", http.StatusFound)
	} else {
		http.Redirect(w, r, "/context/dev/all", http.StatusFound)
	}
}

// Handler for context view of the table
func contextHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
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
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/table.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:         "Nodes in " + context + " Context",
		Selector:      "context",
		SelectorName:  context,
		Target:        target,
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		Settings: SettingsData{
			TLSDebugHTTP:   config.DebugHTTP(serviceNameTLS),
			AdminDebugHTTP: config.DebugHTTP(serviceNameAdmin),
		},
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for platform view of the table
func platformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
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
		"tmpl_admin/head.html",
		"tmpl_admin/page-aside.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-header.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:         "Nodes in " + platform + " Platform",
		Selector:      "platform",
		SelectorName:  platform,
		Target:        target,
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		Settings: SettingsData{
			TLSDebugHTTP:   config.DebugHTTP(serviceNameTLS),
			AdminDebugHTTP: config.DebugHTTP(serviceNameAdmin),
		},
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for GET requests to run queries
func queryRunGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/query-run.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-aside.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-header.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get all nodes
	nodes, err := getNodes("active")
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
		Title:         "Query osquery Nodes",
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		UUIDs:         uuids,
		Hosts:         hosts,
		Tables:        osqueryTables,
		TablesVersion: osqueryTablesVersion,
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for POST requests to run queries
func queryRunPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "The query was created successfully"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	var q DistributedQueryRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
		goto response
	}
	// Check CSRF Token
	if checkCSRFToken(q.CSRFToken) {
		// FIXME check validity of query
		// Query can not be empty
		if q.Query == "" {
			responseMessage = "query can not be empty"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
			goto response
		}
		// Prepare and create new query
		queryName := "query_" + generateQueryName()
		query := DistributedQuery{
			Query:      q.Query,
			Name:       queryName,
			Creator:    "Admin",
			Executions: 0,
			Active:     true,
			Completed:  false,
			Deleted:    false,
			Repeat:     0,
		}
		if err := createQuery(query); err != nil {
			responseMessage = "error creating query"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
			goto response
		}
		// Create context target
		if (q.Context != "") && contextExists(q.Context) {
			if err := createQueryTarget(queryName, queryTargetContext, q.Context); err != nil {
				responseMessage = "error creating query context target"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
				goto response
			}
		}
		// Create platform target
		if (q.Platform != "") && checkValidPlatform(q.Platform) {
			if err := createQueryTarget(queryName, queryTargetPlatform, q.Platform); err != nil {
				responseMessage = "error creating query platform target"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
				goto response
			}
		}
		// Create UUIDs target
		// FIXME verify UUIDs
		if len(q.UUIDs) > 0 {
			for _, u := range q.UUIDs {
				if err := createQueryTarget(queryName, queryTargetUUID, u); err != nil {
					responseMessage = "error creating query UUID target"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
					goto response
				}
			}
		}
		// Create hostnames target
		// FIXME verify localnames
		if len(q.Hosts) > 0 {
			for _, h := range q.Hosts {
				if err := createQueryTarget(queryName, queryTargetLocalname, h); err != nil {
					responseMessage = "error creating query hostname target"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
					goto response
				}
			}
		}
	} else {
		responseMessage = "invalid CSRF token"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
response:
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for GET requests to active queries
func queryActiveGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/query-active.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get queries
	queries, err := getQueries("active")
	if err != nil {
		log.Printf("error getting active queries: %v", err)
		return
	}
	// Prepare template data
	templateData := QueryTableTemplateData{
		Title:         "Currently active queries",
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		Queries:       queries,
		Target:        "active",
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for GET requests to completed queries
func queryCompletedGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/query-completed.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get queries
	queries, err := getQueries("completed")
	if err != nil {
		log.Printf("error getting completed queries: %v", err)
		return
	}
	// Prepare template data
	templateData := QueryTableTemplateData{
		Title:         "Completed queries",
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		Queries:       queries,
		Target:        "completed",
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for POST requests to see completed queries
// FIXME It needs CSRF token
func queryActionsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	var q DistributedQueryActionRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&q)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
	// Check CSRF Token
	if checkCSRFToken(q.CSRFToken) {
		switch q.Action {
		case "delete":
			for _, n := range q.Names {
				err := deleteQuery(n)
				if err != nil {
					responseMessage = "error deleting query"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				}
			}
		case "complete":
			for _, n := range q.Names {
				err := completeQuery(n)
				if err != nil {
					responseMessage = "error completing query"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				}
			}
		case "activate":
			for _, n := range q.Names {
				err := activateQuery(n)
				if err != nil {
					responseMessage = "error activating query"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				}
			}
		}
	} else {
		responseMessage = "invalid CSRF token"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler GET requests to see query results by name
func queryLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	vars := mux.Vars(r)
	// Extract name
	name, ok := vars["name"]
	if !ok {
		log.Println("error getting name")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"removeBackslash": removeBackslash,
		"pastTimeAgo":     pastTimeAgo,
	}
	// Prepare template
	t, err := template.New("query-logs.html").Funcs(funcMap).ParseFiles(
		"tmpl_admin/query-logs.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts %v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get query by name
	query, err := getQuery(name)
	if err != nil {
		log.Printf("error getting query %v", err)
		return
	}
	// Get query targets
	targets, err := getQueryTargets(name)
	if err != nil {
		log.Printf("error getting targets %v", err)
		return
	}
	// Prepare template data
	templateData := QueryLogsTemplateData{
		Title:         "Query logs " + query.Name,
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		Query:         query,
		QueryTargets:  targets,
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler GET requests for conf
func confGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	vars := mux.Vars(r)
	// Extract context
	// FIXME verify context
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
	// Prepare template
	t, err := template.ParseFiles(
		"tmpl_admin/conf.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts%v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get configuration JSON
	ctx, err := getContext(context)
	if err != nil {
		log.Printf("error getting context %v", err)
		return
	}
	// Prepare template data
	shellQuickAdd, _ := quickAddOneLinerShell(ctx)
	powershellQuickAdd, _ := quickAddOneLinerPowershell(ctx)
	shellQuickRemove, _ := quickRemoveOneLinerShell(ctx)
	powershellQuickRemove, _ := quickRemoveOneLinerPowershell(ctx)
	templateData := ConfTemplateData{
		Title:                 context + " Configuration",
		ConfigurationBlob:     ctx.Configuration,
		ConfigurationHash:     generateOsqueryConfigHash(ctx.Configuration),
		Context:               context,
		QuickAddShell:         shellQuickAdd,
		QuickRemoveShell:      shellQuickRemove,
		QuickAddPowershell:    powershellQuickAdd,
		QuickRemovePowershell: powershellQuickRemove,
		ContextStats:          tmplCtxStats,
		PlatformStats:         tmplPlatStats,
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler POST requests for conf
func confPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	vars := mux.Vars(r)
	// Extract context
	// FIXME verify context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	var c ConfigurationRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(c.CSRFToken) {
			configuration, err := base64.StdEncoding.DecodeString(c.ConfigurationB64)
			if err != nil {
				responseMessage = "error decoding configuration"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
			}
			err = updateConfiguration(context, string(configuration))
			if err != nil {
				responseMessage = "error saving configuration"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
			} else {
				responseMessage = "Configuration saved successfully"
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for node view
func nodeHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), false)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		log.Println("error getting uuid")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"removeBackslash": removeBackslash,
		"pastTimeAgo":     pastTimeAgo,
	}
	// Prepare template
	t, err := template.New("node.html").Funcs(funcMap).ParseFiles(
		"tmpl_admin/node.html",
		"tmpl_admin/head.html",
		"tmpl_admin/page-header.html",
		"tmpl_admin/page-sidebar.html",
		"tmpl_admin/page-aside.html")
	if err != nil {
		log.Printf("error getting table template: %v", err)
		return
	}
	// Get stats for all contexts
	contexts, err := getAllContexts()
	if err != nil {
		log.Printf("error getting contexts%v", err)
		return
	}
	tmplCtxStats, err := getContextStats(contexts)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get stats for all platforms
	platforms, err := getAllPlatforms()
	if err != nil {
		log.Printf("error getting platforms: %v", err)
		return
	}
	tmplPlatStats, err := getPlatformStats(platforms)
	if err != nil {
		log.Printf("error getting context stats: %v", err)
		return
	}
	// Get node by UUID
	node, err := getNodeByUUID(uuid)
	if err != nil {
		log.Printf("error getting node %v", err)
		return
	}
	// Check if location is enabled, and if so prepare data
	// FIXME needs rewriting
	/*var locationData LocationData
	if geolocConfig.Maps {
		geoloc, err := getGeoLocationIPAddress(node.IPAddress)
		if err != nil {
			log.Printf("error getting geo location data %v", err)
		}
		locationData = LocationData{
			GoogleMapsURL: getGoogleMapsURL(),
			LastLocation:  geoloc,
		}
	}*/
	// Prepare template data
	templateData := NodeTemplateData{
		Title:         "Node View " + node.UUID,
		PostgresLogs:  logConfig.Postgres,
		Node:          node,
		ContextStats:  tmplCtxStats,
		PlatformStats: tmplPlatStats,
		LocationShow:  false,
		Location:      LocationData{},
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for multi node action
func nodeMultiActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	var m NodeMultiActionRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&m)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(m.CSRFToken) {
			switch m.Action {
			case "delete":
				okCount := 0
				errCount := 0
				for _, u := range m.UUIDs {
					err := archiveDeleteOsqueryNodeByUUID(u)
					if err != nil {
						errCount++
						log.Printf("error deleting node %s %v", u, err)
					} else {
						okCount++
					}
				}
				if errCount == 0 {
					responseMessage = fmt.Sprintf("%d Node(s) have been deleted successfully", okCount)
				} else {
					responseMessage = fmt.Sprintf("Error deleting %d node(s)", errCount)
					responseCode = http.StatusInternalServerError
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for single node action
func nodeActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		log.Println("error getting uuid")
		return
	}
	var n NodeActionRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&n)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(n.CSRFToken) {
			switch n.Action {
			case "delete":
				err := archiveDeleteOsqueryNodeByUUID(uuid)
				if err != nil {
					responseMessage = "error deleting node"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				} else {
					responseMessage = "Node has been deleted successfully"
				}
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for POST request for settings
func settingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, config.DebugHTTP(serviceNameAdmin), true)
	/*vars := mux.Vars(r)
	// Extract uuid
	uuid, ok := vars["uuid"]
	if !ok {
		log.Println("error getting uuid")
		return
	}*/
	var s SettingsRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&s)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(s.CSRFToken) {
			var serviceToChange string
			switch s.Service {
			case serviceTLS:
				serviceToChange = serviceNameTLS
			case serviceAdmin:
				serviceToChange = serviceNameAdmin
			}
			err := config.SetBoolean(s.DebugHTTP, serviceToChange, DebugHTTP)
			if err != nil {
				responseMessage = "error changing settings"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
			} else {
				responseMessage = "Settings updated successfully"
			}
		} else {
			responseMessage = "invalid CSRF token"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
		}
	}
	// Prepare response
	response, err := json.Marshal(AdminResponse{Message: responseMessage})
	if err != nil {
		log.Printf("error formating response [ %v ]", err)
		responseCode = http.StatusInternalServerError
		response = []byte("error formating response")
	}
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(responseCode)
	w.Write(response)
}

// Handler for downloading packages
/*
func packageHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, adminConfig.DebugHTTP, false)
	vars := mux.Vars(r)
	// Extract context
	// FIXME verify context
	context, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Extract platform
	// FIXME verify platform
	platform, ok := vars["platform"]
	if !ok {
		log.Println("error getting platform")
		return
	}
	// Serve file if values are valid
	if checkValidPackagePlatform(context, platform) {
		_, file := path.Split(tlsConfig.Contexts[context][platform])
		w.Header().Set("Content-Disposition", "attachment; filename="+file)
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, tlsConfig.Contexts[context][platform])
	}
}
*/
