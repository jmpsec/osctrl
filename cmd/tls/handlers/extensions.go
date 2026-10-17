package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	maxBodyExtensions        = 16 * 1024 // 16 KiB — osctrld extension list request with status
	maxBodyExtensionDownload = 1024      // 1 KiB — osctrld extension download request
)

// osctrldRequest checks the environment in the path, reads a body of at most
// max bytes into v and checks its secret. It writes the error response and
// returns false when any step fails.
func (h *HandlersTLS) osctrldRequest(w http.ResponseWriter, r *http.Request, max int64, v any, secret func() string) (environments.TLSEnvironment, bool) {
	envVar := r.PathValue("env")
	if !utils.CheckUUID(envVar) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return environments.TLSEnvironment{}, false
	}
	env, err := h.EnvCache.GetByUUID(r.Context(), envVar)
	if err != nil {
		log.Err(err).Msg("error getting environment")
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return env, false
	}
	if h.debugHTTPAll() {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	body, err := readBody(w, r, max)
	if err != nil {
		log.Err(err).Msg("error reading POST body")
		if !isMaxBytesError(err) {
			utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		}
		return env, false
	}
	if err := json.Unmarshal(body, v); err != nil {
		log.Err(err).Msg("error parsing POST body")
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return env, false
	}
	if !h.checkValidSecret(secret(), env) {
		utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
		return env, false
	}
	return env, true
}

// ExtensionsHandler returns the osquery extensions osctrld should run: the
// environment's, plus the node's own when the request names a node of this
// environment. It records the extension status that node reports.
func (h *HandlersTLS) ExtensionsHandler(w http.ResponseWriter, r *http.Request) {
	var t types.OsctrldExtensionsRequest
	env, ok := h.osctrldRequest(w, r, maxBodyExtensions, &t, func() string { return t.Secret })
	if !ok {
		return
	}
	if t.Platform == "" && t.Arch == "" {
		// An osctrld from before extensions: nothing to serve, nothing to record
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, []types.OsctrldExtensionEntry{})
		return
	}
	if !extensions.ValidPlatform(t.Platform, t.Arch) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	now := time.Now()
	// The UUID is untrusted: only a node of this environment gets its own
	// extensions, keyed by the stored (upper-case) UUID.
	nodeUUID := ""
	if utils.CheckUUID(t.UUID) {
		if node, err := h.Nodes.GetByUUIDEnv(t.UUID, env.ID); err == nil {
			nodeUUID = node.UUID
		}
	}
	if nodeUUID != "" && len(t.Status) > 0 {
		if err := h.Extensions.RecordStatus(nodeUUID, env.ID, t.Status, now); err != nil {
			log.Err(err).Msgf("node UUID: %s in %s environment: error recording osctrld extension status", nodeUUID, env.Name)
		}
	}
	entries, err := h.Extensions.EffectiveSet(env.ID, nodeUUID, t.Platform, t.Arch, now)
	if err != nil {
		log.Err(err).Msgf("error getting extensions for %s environment", env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	for i := range entries {
		entries[i].URL = "/" + env.UUID + "/" + environments.DefaultExtensionPath
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, entries)
}

// ExtensionDownloadHandler streams one extension binary assigned in the
// environment, chunk by chunk.
func (h *HandlersTLS) ExtensionDownloadHandler(w http.ResponseWriter, r *http.Request) {
	var t types.OsctrldDownloadRequest
	env, ok := h.osctrldRequest(w, r, maxBodyExtensionDownload, &t, func() string { return t.Secret })
	if !ok {
		return
	}
	sha := t.SHA256
	if !extensions.ValidSHA256(sha) {
		utils.HTTPResponse(w, "", http.StatusBadRequest, []byte(""))
		return
	}
	in, err := h.Extensions.InEnvSet(env.ID, sha)
	if err != nil {
		log.Err(err).Msgf("error checking extension %s for %s environment", sha, env.Name)
		utils.HTTPResponse(w, "", http.StatusInternalServerError, []byte(""))
		return
	}
	if !in {
		utils.HTTPResponse(w, "", http.StatusNotFound, []byte(""))
		return
	}
	size, err := h.Extensions.FileSize(sha)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, extensions.ErrNotFound) {
			code = http.StatusNotFound
		}
		utils.HTTPResponse(w, "", code, []byte(""))
		return
	}
	w.Header().Set(utils.ContentType, utils.OctetStream)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	n, err := h.Extensions.StreamFile(r.Context(), sha, w)
	if err == nil {
		return
	}
	if n == 0 {
		// Nothing sent yet (e.g. replaced since the checks): headers can still change.
		w.Header().Del("Content-Length")
		code := http.StatusInternalServerError
		if errors.Is(err, extensions.ErrNotFound) {
			code = http.StatusNotFound
		}
		utils.HTTPResponse(w, "", code, []byte(""))
		return
	}
	// Mid-stream: the short body against Content-Length tells osctrld it failed.
	log.Debug().Err(err).Msgf("extension %s for %s environment: stream stopped after %d bytes", sha, env.Name, n)
}
