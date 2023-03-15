package handlers

import (
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
)

// FaviconHandler for the favicon
func (h *HandlersAdmin) FaviconHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), false)
	w.Header().Set(utils.ContentType, "image/png")
	http.ServeFile(w, r, "/static/favicon.png")
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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, errorContent)
}

// RootHandler - Handler for the root path
func (h *HandlersAdmin) RootHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), false)
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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), false)
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
	permissions, err := h.Users.GetAccess(usernameVar)
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
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironment), false)
	vars := mux.Vars(r)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey("session")).(sessions.ContextValue)
	// Extract environment
	envVar, ok := vars["env"]
	if !ok {
		log.Println("environment is missing")
		h.Inc(metricAdminErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Printf("error getting environment %s - %v", envVar, err)
		h.Inc(metricAdminErr)
		return
	}
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
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
	// Check if carve is archived already
	carve, err := h.Carves.GetBySession(carveSession)
	if !ok {
		h.Inc(metricAdminErr)
		log.Println("error getting carve")
		return
	}
	var archived *carves.CarveResult
	if !carve.Archived {
		archived, err = h.Carves.Archive(carveSession, h.CarvesFolder)
		if err != nil {
			h.Inc(metricAdminErr)
			log.Printf("error archiving results %v", err)
			return
		}
		if archived == nil {
			h.Inc(metricAdminErr)
			log.Printf("empty archive %v", err)
			return
		}
		if err := h.Carves.ArchiveCarve(carveSession, archived.File); err != nil {
			h.Inc(metricAdminErr)
			log.Printf("error archiving carve %v", err)
		}
	}
	archived = &carves.CarveResult{
		Size: int64(carve.CarveSize),
		File: carve.ArchivePath,
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Carve download")
	}
	if h.Carves.Carver == settings.CarverS3 {
		downloadURL, err := h.Carves.S3.GetDownloadLink(carve)
		if err != nil {
			h.Inc(metricAdminErr)
			log.Printf("error getting carve link - %v", err)
			return
		}
		http.Redirect(w, r, downloadURL, http.StatusFound)
	} else {
		// Send response
		w.Header().Set("Content-Description", "File Carve Download")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename="+archived.File)
		w.Header().Set("Content-Transfer-Encoding", "binary")
		w.Header().Set("Connection", "Keep-Alive")
		w.Header().Set("Expires", "0")
		w.Header().Set("Cache-Control", "must-revalidate, post-check=0, pre-check=0")
		w.Header().Set("Pragma", "public")
		w.Header().Set("Content-Length", strconv.FormatInt(archived.Size, 10))
		w.WriteHeader(http.StatusOK)
		h.Inc(metricAdminOK)
		var fileReader io.Reader
		fileReader, _ = os.Open(archived.File)
		_, _ = io.Copy(w, fileReader)
	}
	h.Inc(metricAdminOK)
}
