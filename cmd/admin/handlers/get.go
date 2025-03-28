package handlers

import (
	"io"
	"net/http"
	"os"

	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// FaviconHandler for the favicon
func (h *HandlersAdmin) FaviconHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	w.Header().Set(utils.ContentType, "image/png")
	http.ServeFile(w, r, "/static/favicon.png")
}

// HealthHandler for health requests
func (h *HandlersAdmin) HealthHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// ErrorHandler for error requests
func (h *HandlersAdmin) ErrorHandler(w http.ResponseWriter, r *http.Request) {
	// Send response
	utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(errorContent))
}

// ForbiddenHandler for forbidden error requests
func (h *HandlersAdmin) ForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	// Debug HTTP for environment
	utils.DebugHTTPDump(r, true)
	// Send response
	utils.HTTPResponse(w, "", http.StatusForbidden, errorContent)
}

// RootHandler - Handler for the root path
func (h *HandlersAdmin) RootHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// PermissionsGETHandler for platform/environment stats in JSON
func (h *HandlersAdmin) PermissionsGETHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	// Extract username and verify
	usernameVar := r.PathValue("username")
	if usernameVar == "" || !h.Users.Exists(usernameVar) {
		if h.Settings.DebugService(config.ServiceAdmin) {
			log.Debug().Msg("DebugService: error getting username")
		}
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Get permissions
	permissions, err := h.Users.GetAccess(usernameVar)
	if err != nil {
		log.Err(err).Msg("error getting permissions")
	}
	// Serve JSON
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, permissions)
}

// CarvesDownloadHandler for GET requests to download carves
func (h *HandlersAdmin) CarvesDownloadHandler(w http.ResponseWriter, r *http.Request) {
	utils.DebugHTTPDump(r, false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		return
	}
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		return
	}
	// Extract id to download
	carveSession := r.PathValue("sessionid")
	if carveSession == "" {
		log.Info().Msg("empty carve session")
		return
	}
	// Check if carve is archived already
	carve, err := h.Carves.GetBySession(carveSession)
	if err != nil {
		log.Err(err).Msgf("error getting carve")
		return
	}
	var archived *carves.CarveResult
	if !carve.Archived {
		archived, err = h.Carves.Archive(carveSession, h.CarvesFolder)
		if err != nil {
			log.Err(err).Msgf("error archiving results")
			return
		}
		if archived == nil {
			log.Info().Msg("empty archive")
			return
		}
		if err := h.Carves.ArchiveCarve(carveSession, archived.File); err != nil {
			log.Err(err).Msgf("error archiving carve")
		}
	}
	archived = &carves.CarveResult{
		Size: int64(carve.CarveSize),
		File: carve.ArchivePath,
	}
	if h.Settings.DebugService(config.ServiceAdmin) {
		log.Debug().Msg("DebugService: Carve download")
	}
	if h.Carves.Carver == config.CarverS3 {
		downloadURL, err := h.Carves.S3.GetDownloadLink(carve)
		if err != nil {
			log.Err(err).Msg("error getting carve link")
			return
		}
		http.Redirect(w, r, downloadURL, http.StatusFound)
	} else {
		// Send response
		utils.HTTPDownload(w, "File Carve Download", archived.File, archived.Size)
		w.WriteHeader(http.StatusOK)
		var fileReader io.Reader
		fileReader, _ = os.Open(archived.File)
		_, _ = io.Copy(w, fileReader)
	}
}
