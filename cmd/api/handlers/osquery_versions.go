package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// osqueryMaxBody caps the JSON bodies of the osquery version endpoints.
const osqueryMaxBody = 64 << 10

// requireOsqueryAdmin allows super admins only and audits every denial.
func (h *HandlersApi) requireOsqueryAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		h.AuditLog.Denied(ctx[ctxUser], r.URL.Path, utils.GetIP(r), "permission check failed", auditlog.LogTypeSetting, auditlog.NoEnvironment)
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use osquery versions API by user %s", ctx[ctxUser]))
		return "", false
	}
	return ctx[ctxUser], true
}

// osqueryError maps pkg/osqueryversions errors to HTTP statuses. An unknown
// version in a target or pin request is the caller's mistake: 400.
func osqueryError(w http.ResponseWriter, err error, notFound int) {
	switch {
	case errors.Is(err, osqueryversions.ErrInvalid):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
	case errors.Is(err, osqueryversions.ErrInUse):
		apiErrorResponse(w, "version is used by an environment target or a node pin", http.StatusConflict, err)
	case errors.Is(err, osqueryversions.ErrNotFound):
		apiErrorResponse(w, "version not found", notFound, err)
	default:
		log.Err(err).Msg("osquery versions API error")
		apiErrorResponse(w, "internal error", http.StatusInternalServerError, err)
	}
}

// decodeOsqueryBody decodes one JSON object, refusing unknown fields (a
// misspelled expires_at would pin forever) and anything after the object.
func decodeOsqueryBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, osqueryMaxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		var tooBig *http.MaxBytesError
		if e := dec.Decode(&struct{}{}); errors.As(e, &tooBig) {
			err = e
		} else if e != io.EOF {
			err = errors.New("unexpected data after the JSON object")
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			apiErrorResponse(w, "request body too large", http.StatusRequestEntityTooLarge, err)
		} else {
			apiErrorResponse(w, "invalid request body: "+err.Error(), http.StatusBadRequest, err)
		}
		return false
	}
	return true
}

// osqueryVersionPath returns the {version} path value, answering 400 when it is not a valid version.
func osqueryVersionPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	version := r.PathValue("version")
	if !osqueryversions.ValidVersion(version) {
		apiErrorResponse(w, "invalid osquery version", http.StatusBadRequest, nil)
		return "", false
	}
	return version, true
}

func toOsqueryVersionView(v osqueryversions.VersionView) types.OsqueryVersionView {
	out := types.OsqueryVersionView{Version: v.Version, InUse: v.InUse, Entries: make([]types.OsqueryVersionEntry, 0, len(v.Entries))}
	for _, e := range v.Entries {
		out.Entries = append(out.Entries, types.OsqueryVersionEntry{
			Platform: e.Platform, Arch: e.Arch, Format: e.Format, SHA256: e.SHA256, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt,
		})
	}
	return out
}

// auditDigests lists entries as platform/arch/format=sha256, adding
// " (was <old>)" when before holds another digest for the combination.
// PutEntries refuses repeated combinations, so the line holds at most five.
func auditDigests(entries, before []osqueryversions.DigestEntry) string {
	key := func(e osqueryversions.DigestEntry) string { return e.Platform + "/" + e.Arch + "/" + e.Format }
	old := make(map[string]string, len(before))
	for _, e := range before {
		old[key(e)] = e.SHA256
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		p := key(e) + "=" + e.SHA256
		if was, ok := old[key(e)]; ok && was != e.SHA256 {
			p += " (was " + was + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// OsqueryVersionsListHandler - GET Handler for the osquery version library
// @Summary List osquery versions
// @Description Returns the osquery versions osctrld can roll out, with the SHA-256 of each official package and whether a target or pin uses the version. Super admins only.
// @Tags osquery
// @Produce json
// @Success 200 {array} types.OsqueryVersionView
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/osquery/versions [get]
func (h *HandlersApi) OsqueryVersionsListHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireOsqueryAdmin(w, r); !ok {
		return
	}
	views, err := h.OsqueryVersions.ListVersions()
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	out := make([]types.OsqueryVersionView, 0, len(views))
	for _, v := range views {
		out = append(out, toOsqueryVersionView(v))
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// OsqueryVersionPutHandler - PUT Handler to add or replace the digests of a version
// @Summary Set osquery version digests
// @Description Adds or replaces the package SHA-256 digests of a version (linux deb/rpm amd64/arm64, darwin pkg universal), each combination at most once. Unknown body fields are refused. Windows is not supported. Changing a digest of a version used by a target or pin is refused with 409. Super admins only.
// @Tags osquery
// @Accept json
// @Produce json
// @Param version path string true "Osquery version, for example 5.13.0"
// @Param request body types.OsqueryVersionPutRequest true "Digests"
// @Success 200 {object} types.OsqueryVersionView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Version in use"
// @Failure 413 {object} types.ApiErrorResponse "Request body too large"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/osquery/versions/{version} [put]
func (h *HandlersApi) OsqueryVersionPutHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireOsqueryAdmin(w, r)
	if !ok {
		return
	}
	version, ok := osqueryVersionPath(w, r)
	if !ok {
		return
	}
	var req types.OsqueryVersionPutRequest
	if !decodeOsqueryBody(w, r, &req) {
		return
	}
	entries := make([]osqueryversions.DigestEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		entries = append(entries, osqueryversions.DigestEntry{Platform: e.Platform, Arch: e.Arch, Format: e.Format, SHA256: e.SHA256})
	}
	// The digests before the write give the audit line the ones replaced.
	before, err := h.OsqueryVersions.GetEntries(version)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if err := h.OsqueryVersions.PutEntries(version, entries, user); err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("set osquery version %s: %s", version, auditDigests(entries, before)), utils.GetIP(r))
	// ponytail: scans the whole library; add a per-version view if it ever grows large.
	views, err := h.OsqueryVersions.ListVersions()
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	for _, v := range views {
		if v.Version == version {
			utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toOsqueryVersionView(v))
			return
		}
	}
	apiErrorResponse(w, "version not found", http.StatusNotFound, nil)
}

// OsqueryVersionDeleteHandler - DELETE Handler to remove a version from the library
// @Summary Remove osquery version
// @Description Removes a version and its digests from the library. Refused with 409 while an environment target or an unexpired node pin uses it. Super admins only.
// @Tags osquery
// @Produce json
// @Param version path string true "Osquery version, for example 5.13.0"
// @Success 200 {object} types.ApiGenericResponse
// @Failure 400 {object} types.ApiErrorResponse "Invalid version"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Version in use"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/osquery/versions/{version} [delete]
func (h *HandlersApi) OsqueryVersionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireOsqueryAdmin(w, r)
	if !ok {
		return
	}
	version, ok := osqueryVersionPath(w, r)
	if !ok {
		return
	}
	removed, err := h.OsqueryVersions.GetEntries(version)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if err := h.OsqueryVersions.DeleteVersion(version); err != nil {
		osqueryError(w, err, http.StatusNotFound)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("removed osquery version %s: %s", version, auditDigests(removed, nil)), utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: "osquery version removed"})
}

// serveEnvOsquery writes the environment's target and per-version host counts.
func (h *HandlersApi) serveEnvOsquery(w http.ResponseWriter, envID uint) {
	resp := types.EnvOsqueryResponse{Counts: []types.OsqueryVersionHostCount{}}
	var err error
	if resp.Available, err = h.OsqueryVersions.VersionNames(); err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	t, err := h.OsqueryVersions.GetEnvTarget(envID)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if t != nil {
		resp.Target = &types.OsqueryTargetView{Version: t.Version, RequestID: t.RequestID, UpdatedBy: t.UpdatedBy, UpdatedAt: t.UpdatedAt}
	}
	counts, err := h.Nodes.GetOsqueryVersionCountsByEnv(envID)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	for _, c := range counts {
		resp.Counts = append(resp.Counts, types.OsqueryVersionHostCount{Version: c.Version, Count: c.Count})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// EnvOsqueryGetHandler - GET Handler for an environment's osquery target
// @Summary Get environment osquery target
// @Description Returns the osquery version the environment is rolled out to and the number of its hosts per installed version, plus the names (no digests) of the library versions it can be set to. The installed versions are reported by the hosts and are untrusted. Environment admins.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} types.EnvOsqueryResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/osquery/{env} [get]
func (h *HandlersApi) EnvOsqueryGetHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return
	}
	h.serveEnvOsquery(w, env.ID)
}

// EnvOsqueryPutHandler - PUT Handler to set an environment's osquery target
// @Summary Set environment osquery target
// @Description Rolls the environment out to a version of the library. Hosts at or above it are left alone; osctrld upgrades the others when osqueryd is running. Setting the same version again retries hosts that rejected it. Unknown body fields are refused, and so is expires_at: environment targets do not expire (use a node pin for a temporary override). Environment admins.
// @Tags environments
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.OsqueryTargetRequest true "Target version"
// @Success 200 {object} types.EnvOsqueryResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request or version not in the library"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 413 {object} types.ApiErrorResponse "Request body too large"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/osquery/{env} [put]
func (h *HandlersApi) EnvOsqueryPutHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return
	}
	var req types.OsqueryTargetRequest
	if !decodeOsqueryBody(w, r, &req) {
		return
	}
	if req.ExpiresAt != nil {
		apiErrorResponse(w, "environment targets do not expire; use a node pin for a temporary override", http.StatusBadRequest, nil)
		return
	}
	if _, err := h.OsqueryVersions.SetEnvTarget(env.ID, req.Version, ctx[ctxUser]); err != nil {
		osqueryError(w, err, http.StatusBadRequest)
		return
	}
	h.AuditLog.EnvAction(ctx[ctxUser], fmt.Sprintf("set osquery target of environment %s to %s", env.Name, req.Version), utils.GetIP(r), env.ID)
	h.serveEnvOsquery(w, env.ID)
}

// EnvOsqueryDeleteHandler - DELETE Handler to clear an environment's osquery target
// @Summary Clear environment osquery target
// @Description Stops rolling the environment out; hosts keep the version they have. Clearing an unset target answers 200 and is not audited. Environment admins.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} types.EnvOsqueryResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/osquery/{env} [delete]
func (h *HandlersApi) EnvOsqueryDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, ctx, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return
	}
	cleared, err := h.OsqueryVersions.ClearEnvTarget(env.ID)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if cleared {
		h.AuditLog.EnvAction(ctx[ctxUser], "cleared osquery target of environment "+env.Name, utils.GetIP(r), env.ID)
	}
	h.serveEnvOsquery(w, env.ID)
}

// serveNodeOsquery writes the node's pin, effective target, installed version,
// whether its platform is unsupported (windows) and the last stored upgrade
// report. A pin or report recorded for another
// environment is not applied by osctrl-tls and is treated as absent.
func (h *HandlersApi) serveNodeOsquery(w http.ResponseWriter, env environments.TLSEnvironment, node nodes.OsqueryNode) {
	uuid := node.UUID
	resp := types.NodeOsqueryResponse{
		InstalledVersion:    node.OsqueryVersion,
		PlatformUnsupported: strings.EqualFold(node.Platform, "windows"),
	}
	var err error
	if resp.Available, err = h.OsqueryVersions.VersionNames(); err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	pin, err := h.OsqueryVersions.GetPin(uuid)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if pin != nil && pin.EnvironmentID == env.ID {
		resp.Pin = &types.OsqueryPinView{Version: pin.Version, RequestID: pin.RequestID, ExpiresAt: pin.ExpiresAt, UpdatedBy: pin.UpdatedBy, UpdatedAt: pin.UpdatedAt}
		if !pin.Expired(time.Now()) {
			resp.Target = &types.OsqueryEffectiveTarget{Version: pin.Version, Source: "pin"}
		}
	}
	if resp.Target == nil {
		t, err := h.OsqueryVersions.GetEnvTarget(env.ID)
		if err != nil {
			osqueryError(w, err, http.StatusInternalServerError)
			return
		}
		if t != nil {
			resp.Target = &types.OsqueryEffectiveTarget{Version: t.Version, Source: "environment"}
		}
	}
	if h.FlagsOverrides != nil {
		st, err := h.FlagsOverrides.Status(uuid)
		if err != nil {
			osqueryError(w, err, http.StatusInternalServerError)
			return
		}
		if st != nil && st.EnvironmentID == env.ID && st.UpgradeReportedAt != nil {
			resp.Upgrade = &types.OsqueryUpgradeView{
				Result: st.UpgradeResult, Version: st.UpgradeVersion, Reason: st.UpgradeReason,
				RequestID: st.UpgradeRequestID, ReportedAt: *st.UpgradeReportedAt,
			}
		}
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// NodeOsqueryGetHandler - GET Handler for a node's osquery upgrade state
// @Summary Get node osquery upgrade state
// @Description Returns the node's pin, the version it is rolled out to (the unexpired pin, else the environment target), the osquery version it reports as installed, whether its platform is unsupported by osctrld upgrades (windows), the names (no digests) of the library versions it can be pinned to and the last upgrade report of its osctrld. The installed version and the upgrade result, version, reason and request_id are reported by the host and are untrusted; reported_at is the server's receive time. Environment admins.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeOsqueryResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/osquery [get]
func (h *HandlersApi) NodeOsqueryGetHandler(w http.ResponseWriter, r *http.Request) {
	env, node, _, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	h.serveNodeOsquery(w, env, node)
}

// NodeOsqueryPutHandler - PUT Handler to pin a node to an osquery version
// @Summary Pin node osquery version
// @Description Pins the node to a version of the library, overriding the environment target, optionally until expires_at (RFC 3339, in the future). Changing only the expiry of the pinned version (in the same environment) keeps its request_id, so a version the host rejected is not retried; setting the same version with the same expiry again (or another version) gets a new request_id and retries. Unknown body fields are refused. The installed version and the upgrade result, version, reason and request_id are reported by the host and are untrusted. Environment admins.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param request body types.OsqueryTargetRequest true "Pin"
// @Success 200 {object} types.NodeOsqueryResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request, version not in the library or expiry in the past"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 413 {object} types.ApiErrorResponse "Request body too large"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/osquery [put]
func (h *HandlersApi) NodeOsqueryPutHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	var req types.OsqueryTargetRequest
	if !decodeOsqueryBody(w, r, &req) {
		return
	}
	if _, err := h.OsqueryVersions.SetPin(node.UUID, env.ID, req.Version, req.ExpiresAt, user); err != nil {
		osqueryError(w, err, http.StatusBadRequest)
		return
	}
	expires := "never"
	if req.ExpiresAt != nil {
		expires = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	h.AuditLog.NodeAction(user, fmt.Sprintf("pinned node %s to osquery %s (expires %s)", node.UUID, req.Version, expires), utils.GetIP(r), env.ID)
	h.serveNodeOsquery(w, env, node)
}

// NodeOsqueryDeleteHandler - DELETE Handler to remove a node's osquery pin
// @Summary Remove node osquery pin
// @Description Removes the node's pin so it follows the environment target. Removing an absent pin answers 200 and is not audited. The installed version and the upgrade result, version, reason and request_id are reported by the host and are untrusted. Environment admins.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeOsqueryResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/osquery [delete]
func (h *HandlersApi) NodeOsqueryDeleteHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	removed, err := h.OsqueryVersions.DeletePin(node.UUID)
	if err != nil {
		osqueryError(w, err, http.StatusInternalServerError)
		return
	}
	if removed {
		h.AuditLog.NodeAction(user, "removed osquery pin of node "+node.UUID, utils.GetIP(r), env.ID)
	}
	h.serveNodeOsquery(w, env, node)
}
