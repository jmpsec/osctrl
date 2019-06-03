package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/context"
	"github.com/javuto/osctrl/pkg/queries"

	"github.com/gorilla/mux"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// Empty default osquery configuration
const emptyConfiguration string = "data/osquery-empty.conf"

// Handle testing requests
func testingHTTPHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("test"))
}

// Handle error requests
func errorHTTPHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	// Send response
	w.Header().Set("Content-Type", JSONApplicationUTF8)
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte("oh no..."))
}

// Handler for the favicon
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)

	w.Header().Set("Content-Type", "image/png")
	http.ServeFile(w, r, "./static/favicon.png")
}

// Handler for login page for GET requests
func loginGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
}

// Handler for login page for POST requests
func loginPOSTHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
	if access, user := adminUsers.CheckLoginCredentials(l.Username, l.Password); access {
		session, err := store.Get(r, projectName)
		if err != nil {
			log.Printf("New session - %v", err)
		}
		csrfToken := generateCSRF()
		session.Values["authenticated"] = true
		session.Values["user"] = l.Username
		session.Values["admin"] = user.Admin
		session.Values["csrftoken"] = csrfToken
		_ = session.Save(r, w)
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
	_, _ = w.Write(response)
}

// Handle POST requests to logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		_ = session.Save(r, w)
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
	_, _ = w.Write(response)
}

// Handler for the root path
func rootHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
	// Redirect to table for all nodes
	// FIXME there should not be static context
	if ctxs.Exists("corp") {
		http.Redirect(w, r, "/context/corp/all", http.StatusFound)
	} else {
		http.Redirect(w, r, "/context/dev/all", http.StatusFound)
	}
}

// Handler for context view of the table
func contextHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for platform view of the table
func platformHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for GET requests to run queries
func queryRunGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
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
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
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
		newQuery := queries.DistributedQuery{
			Query:      q.Query,
			Name:       queryName,
			Creator:    "Admin",
			Executions: 0,
			Active:     true,
			Completed:  false,
			Deleted:    false,
			Repeat:     0,
			Type:       queries.StandardQueryType,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			responseMessage = "error creating query"
			responseCode = http.StatusInternalServerError
			log.Printf("%s %v", responseMessage, err)
			goto response
		}
		// Create context target
		if (q.Context != "") && ctxs.Exists(q.Context) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetContext, q.Context); err != nil {
				responseMessage = "error creating query context target"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
				goto response
			}
		}
		// Create platform target
		if (q.Platform != "") && checkValidPlatform(q.Platform) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetPlatform, q.Platform); err != nil {
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
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, u); err != nil {
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
				if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetLocalname, h); err != nil {
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
	_, _ = w.Write(response)
}

// Handler for GET requests to queries
func queryListGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
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
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
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
				err := queriesmgr.Delete(n)
				if err != nil {
					responseMessage = "error deleting query"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				}
			}
		case "complete":
			for _, n := range q.Names {
				err := queriesmgr.Complete(n)
				if err != nil {
					responseMessage = "error completing query"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				}
			}
		case "activate":
			for _, n := range q.Names {
				err := queriesmgr.Activate(n)
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
	_, _ = w.Write(response)
}

// Handler GET requests to see query results by name
func queryLogsHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler GET requests for /conf
func confGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler GET requests for /enroll
func enrollGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP:        settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler POST requests for saving configuration
func confPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	vars := mux.Vars(r)
	// Extract context
	contextVar, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Verify context
	if !ctxs.Exists(contextVar) {
		log.Printf("error unknown context (%s)", contextVar)
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
			err = ctxs.UpdateConfiguration(contextVar, string(configuration))
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
	_, _ = w.Write(response)
}

// Handler POST requests for saving intervals
func intervalsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	vars := mux.Vars(r)
	// Extract context
	contextVar, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Verify context
	if !ctxs.Exists(contextVar) {
		log.Printf("error unknown context (%s)", contextVar)
		return
	}
	var c IntervalsRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(c.CSRFToken) {
			err = ctxs.UpdateIntervals(contextVar, c.ConfigInterval, c.LogInterval, c.QueryInterval)
			if err != nil {
				responseMessage = "error updating intervals"
				responseCode = http.StatusInternalServerError
				log.Printf("%s %v", responseMessage, err)
			} else {
				responseMessage = "Intervals updated successfully"
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
	_, _ = w.Write(response)
}

// Handler POST requests for expiring enroll links
func expirationPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	vars := mux.Vars(r)
	// Extract context
	contextVar, ok := vars["context"]
	if !ok {
		log.Println("error getting context")
		return
	}
	// Verify context
	if !ctxs.Exists(contextVar) {
		log.Printf("error unknown context (%s)", contextVar)
		return
	}
	var e ExpirationRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&e)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(e.CSRFToken) {
			switch e.Type {
			case "enroll":
				switch e.Action {
				case "expire":
					err = ctxs.ExpireEnroll(contextVar)
					if err != nil {
						responseMessage = "error expiring enroll"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					}
				case "extend":
					err = ctxs.RotateEnrollPath(contextVar)
					if err != nil {
						responseMessage = "error extending enroll"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					}
				}
			case "remove":
				switch e.Action {
				case "expire":
					err = ctxs.ExpireRemove(contextVar)
					if err != nil {
						responseMessage = "error expiring enroll"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					}
				case "extend":
					err = ctxs.RotateRemove(contextVar)
					if err != nil {
						responseMessage = "error extending enroll"
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
	_, _ = w.Write(response)
}

// Handler for node view
func nodeHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
	// Check if location is enabled, and if so prepare data
	// FIXME needs rewriting
	/*var locationData LocationData
	if geolocsettingsmgr.Maps {
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
		Title:          "Node View " + node.UUID,
		PostgresLogs:   logConfig.Postgres,
		Node:           node,
		Contexts:       contexts,
		Platforms:      platforms,
		LocationShow:   false,
		Location:       LocationData{},
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler POST requests for multi node action
func nodeMultiActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
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
					err := nodesmgr.ArchiveDeleteByUUID(u)
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
	_, _ = w.Write(response)
}

// Handler POST requests for single node action
func nodeActionHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
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
				err := nodesmgr.ArchiveDeleteByUUID(uuid)
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
	_, _ = w.Write(response)
}

// Handler GET requests for /contexts
func contextsGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
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
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for POST request for /contexts
func contextsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	var c ContextsRequest
	// Parse request JSON body
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		responseMessage = "error parsing POST body"
		responseCode = http.StatusInternalServerError
		log.Printf("%s %v", responseMessage, err)
	} else {
		// Check CSRF Token
		if checkCSRFToken(c.CSRFToken) {
			switch c.Action {
			case "create":
				// FIXME verify fields
				if !ctxs.Exists(c.Name) {
					_ctx := ctxs.Empty(c.Name, c.Hostname)
					_ctx.Icon = c.Icon
					_ctx.Type = c.Type
					if _ctx.Configuration == "" {
						_ctx.Configuration = context.ReadExternalFile(emptyConfiguration)
					}
					err := ctxs.Create(_ctx)
					if err != nil {
						responseMessage = "error creating context"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					} else {
						responseMessage = "Context created successfully"
					}
				}
			case "delete":
				// FIXME verify fields
				if ctxs.Exists(c.Name) {
					err := ctxs.Delete(c.Name)
					if err != nil {
						responseMessage = "error deleting context"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					} else {
						responseMessage = "Context deleted successfully"
					}
				}
			case "debug":
				// FIXME verify fields
				if ctxs.Exists(c.Name) {
					err := ctxs.ChangeDebugHTTP(c.Name, c.DebugHTTP)
					if err != nil {
						responseMessage = "error changing DebugHTTP"
						responseCode = http.StatusInternalServerError
						log.Printf("%s %v", responseMessage, err)
					} else {
						responseMessage = "DebugHTTP changed successfully"
					}
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
	_, _ = w.Write(response)
}

// Handler GET requests for /settings
func settingsGETHandler(w http.ResponseWriter, r *http.Request) {
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), false)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		log.Println("error getting service")
		return
	}
	// Verify service
	if serviceVar != serviceTLS && serviceVar != serviceAdmin {
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
		Title:          "Manage settings",
		Service:        serviceVar,
		Contexts:       contexts,
		Platforms:      platforms,
		CurrentSettings: _settings,
		AdminDebugHTTP: settingsmgr.DebugHTTP(serviceAdmin),
	}
	if err := t.Execute(w, templateData); err != nil {
		log.Printf("template error %v", err)
		return
	}
}

// Handler for POST request for settings
func settingsPOSTHandler(w http.ResponseWriter, r *http.Request) {
	responseMessage := "OK"
	responseCode := http.StatusOK
	debugHTTPDump(r, settingsmgr.DebugHTTP(serviceAdmin), true)
	vars := mux.Vars(r)
	// Extract service
	serviceVar, ok := vars["service"]
	if !ok {
		log.Println("error getting service")
		return
	}
	// Verify service
	if serviceVar != serviceTLS && serviceVar != serviceAdmin {
		log.Printf("error unknown service (%s)", serviceVar)
		return
	}
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
			switch s.Action {
			case "add":
				// FIXME verify type
				var err error
				switch s.Type {
				case settings.TypeBoolean:
					err = settingsmgr.NewBooleanValue(serviceVar, s.Name, stringToBoolean(s.Value))
				case settings.TypeInteger:
					err = settingsmgr.NewIntegerValue(serviceVar, s.Name, stringToInteger(s.Value))
				case settings.TypeString:
					err = settingsmgr.NewStringValue(serviceVar, s.Name, s.Value)
				}
				if err != nil {
					responseMessage = "error adding setting"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				} else {
					responseMessage = "Setting added successfully"
				}
			case "debug":
				err := settingsmgr.SetBoolean(s.Boolean, serviceVar, settings.DebugHTTP)
				if err != nil {
					responseMessage = "error changing DebugHTTP"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				} else {
					responseMessage = "DebugHTTP changed successfully"
				}
			case "change":
				// FIXME verify type
				var err error
				switch s.Type {
				case settings.TypeBoolean:
					err = settingsmgr.SetBoolean(s.Boolean, serviceVar, s.Name)
				case settings.TypeInteger:
					err = settingsmgr.SetInteger(stringToInteger(s.Value), serviceVar, s.Name)
				case settings.TypeString:
					err = settingsmgr.SetString(s.Value, serviceVar, s.Name)
				}
				if err != nil {
					responseMessage = "error changing setting"
					responseCode = http.StatusInternalServerError
					log.Printf("%s %v", responseMessage, err)
				} else {
					responseMessage = "Setting changed successfully"
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
	_, _ = w.Write(response)
}
