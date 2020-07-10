package handlers

import (
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// osquery
const (
	// osquery version to display tables
	osqueryTablesVersion string = "4.4.0"
	// JSON file with osquery tables data
	osqueryTablesFile string = "data/" + osqueryTablesVersion + ".json"
	// Carved files folder
	carvedFilesFolder string = "carved_files/"
)

// FaviconHandler for the favicon
func (h *HandlersAdmin) FaviconHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	w.Header().Set(utils.ContentType, "image/png")
	http.ServeFile(w, r, "./static/favicon.png")
}

// HealthHandler for health requests
func (h *HandlersAdmin) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricHealthReq)
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
	h.Inc(metricHealthOK)
}

// ErrorHandler for error requests
func (h *HandlersAdmin) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler for forbidden error requests
func (h *HandlersAdmin) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, errorContent)
}

// Handler for the root path
func (h *HandlersAdmin) RootHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	// Redirect to table for active nodes in default environment
	defaultEnvironment := h.Settings.DefaultEnv(settings.ServiceAdmin)
	if h.Envs.Exists(defaultEnvironment) {
		http.Redirect(w, r, "/environment/"+defaultEnvironment+"/active", http.StatusFound)
	} else {
		http.Redirect(w, r, "/environments", http.StatusFound)
	}
}

// PermissionsGETHandler for platform/environment stats in JSON
func (h *HandlersAdmin) PermissionsGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Extract username and verify
	usernameVar, ok := vars["username"]
	if !ok || !h.Users.Exists(usernameVar) {
		if h.Settings.DebugService(settings.ServiceAdmin) {
			log.Printf("DebugService: error getting username")
		}
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Get permissions
	permissions, err := h.Users.GetPermissions(usernameVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error getting permissions %v", err)
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, permissions)
	h.Inc(metricJSONOK)
}

// CarvesDownloadHandler for GET requests to download carves
func (h *HandlersAdmin) CarvesDownloadHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin), false)
	vars := mux.Vars(r)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, users.NoEnvironment) {
		log.Printf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Extract id to download
	carveSession, ok := vars["sessionid"]
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting carve")
		return
	}
	// Prepare file to download
	result, err := h.Carves.Archive(carveSession, carvedFilesFolder)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Printf("error downloading carve - %v", err)
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve download")
	}
	h.Inc(metricAdminOK)
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
