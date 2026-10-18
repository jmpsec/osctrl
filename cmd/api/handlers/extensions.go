package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

const (
	extensionDescriptionMax = 1024
	extensionFilenameMax    = 255
	extensionJSONMaxBody    = 64 << 10
	// extensionUploadMaxBody is the largest file plus room for the
	// multipart framing.
	extensionUploadMaxBody = extensions.MaxFileSize + 1<<20
	// extensionUploadTimeout bounds how long an upload, and the database
	// transaction PutFile holds while reading it, can take.
	extensionUploadTimeout = 10 * time.Minute
)

// requireExtensionsAdmin allows super admins only and audits every denial.
func (h *HandlersApi) requireExtensionsAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissionsContext(r.Context(), ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		h.AuditLog.Denied(ctx[ctxUser], r.URL.Path, utils.GetIP(r), "permission check failed", auditlog.LogTypeSetting, auditlog.NoEnvironment)
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use extensions API by user %s", ctx[ctxUser]))
		return "", false
	}
	return ctx[ctxUser], true
}

// extensionsError maps pkg/extensions errors to HTTP statuses.
func extensionsError(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, extensions.ErrTooLarge), errors.As(err, &tooBig):
		apiErrorResponse(w, "file is larger than 64 MiB", http.StatusRequestEntityTooLarge, err)
	case errors.Is(err, extensions.ErrInvalid), errors.Is(err, extensions.ErrEmpty), errors.Is(err, extensions.ErrTruncated):
		apiErrorResponse(w, err.Error(), http.StatusBadRequest, err)
	case errors.Is(err, extensions.ErrNotFound):
		apiErrorResponse(w, "not found", http.StatusNotFound, err)
	case errors.Is(err, extensions.ErrDuplicate):
		apiErrorResponse(w, "an extension with that name already exists", http.StatusConflict, err)
	case errors.Is(err, extensions.ErrAssigned):
		apiErrorResponse(w, "extension is assigned to environments or nodes", http.StatusConflict, err)
	case errors.Is(err, extensions.ErrKept):
		apiErrorResponse(w, "a host could not remove this command-execution extension", http.StatusConflict, err)
	case errors.Is(err, extensions.ErrCommandExecution), errors.Is(err, extensions.ErrNotCommandExecution):
		apiErrorResponse(w, err.Error(), http.StatusConflict, err)
	default:
		log.Err(err).Msg("extensions API error")
		apiErrorResponse(w, "internal error", http.StatusInternalServerError, err)
	}
}

func toExtensionView(v extensions.ExtensionView) types.ExtensionView {
	files := make([]types.ExtensionFileView, 0, len(v.Files))
	for _, f := range v.Files {
		files = append(files, toExtensionFileView(f))
	}
	return types.ExtensionView{
		ID:               v.ID,
		Name:             v.Name,
		Description:      v.Description,
		Version:          v.Version,
		CommandExecution: v.CommandExecution,
		Files:            files,
		Environments:     int(v.EnvAssignments),
		Nodes:            int(v.NodeAssignments),
		CreatedBy:        v.CreatedBy,
		UpdatedAt:        v.UpdatedAt,
	}
}

func toExtensionFileView(f extensions.ExtensionFile) types.ExtensionFileView {
	return types.ExtensionFileView{
		Platform:  f.Platform,
		Arch:      f.Arch,
		Size:      f.Size,
		SHA256:    f.SHA256,
		Filename:  f.Filename,
		UpdatedAt: f.UpdatedAt,
		UpdatedBy: f.UpdatedBy,
	}
}

// extensionView returns one library entry with its files and counts.
// ponytail: scans the whole library; add a per-ID query if it ever grows large.
func (h *HandlersApi) extensionView(id uint) (types.ExtensionView, error) {
	views, err := h.Extensions.List()
	if err != nil {
		return types.ExtensionView{}, err
	}
	for _, v := range views {
		if v.ID == id {
			return toExtensionView(v), nil
		}
	}
	return types.ExtensionView{}, extensions.ErrNotFound
}

// sanitizeFilename keeps the base name of an uploaded file, without control
// characters and at most extensionFilenameMax bytes of valid UTF-8.
func sanitizeFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	if len(name) > extensionFilenameMax {
		name = strings.ToValidUTF8(name[:extensionFilenameMax], "")
	}
	return name
}

// ExtensionsListHandler - GET Handler for the extensions library
// @Summary List osquery extensions
// @Description Returns the extensions library with each extension's files and assignment counts. Super admins only.
// @Tags extensions
// @Produce json
// @Success 200 {array} types.ExtensionView
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions [get]
func (h *HandlersApi) ExtensionsListHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireExtensionsAdmin(w, r); !ok {
		return
	}
	views, err := h.Extensions.List()
	if err != nil {
		extensionsError(w, err)
		return
	}
	out := make([]types.ExtensionView, 0, len(views))
	for _, v := range views {
		out = append(out, toExtensionView(v))
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// ExtensionsCreateHandler - POST Handler to add an extension
// @Summary Create an osquery extension
// @Description Adds an extension to the library. Command-execution extensions can only be assigned to individual nodes. Super admins only.
// @Tags extensions
// @Accept json
// @Produce json
// @Param request body types.ExtensionCreateRequest true "Extension"
// @Success 201 {object} types.ExtensionView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 409 {object} types.ApiErrorResponse "Name already exists"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions [post]
func (h *HandlersApi) ExtensionsCreateHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireExtensionsAdmin(w, r)
	if !ok {
		return
	}
	var req types.ExtensionCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, extensionJSONMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	if len(req.Description) > extensionDescriptionMax {
		apiErrorResponse(w, fmt.Sprintf("description is longer than %d bytes", extensionDescriptionMax), http.StatusBadRequest, nil)
		return
	}
	e, err := h.Extensions.Create(extensions.Extension{
		Name:             req.Name,
		Description:      req.Description,
		Version:          req.Version,
		CommandExecution: req.CommandExecution,
		CreatedBy:        user,
	})
	if err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("created extension %s (command execution %v)", e.Name, e.CommandExecution), utils.GetIP(r))
	view, err := h.extensionView(e.ID)
	if err != nil {
		extensionsError(w, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, view)
}

// ExtensionsUpdateHandler - PATCH Handler to change an extension
// @Summary Update an osquery extension
// @Description Changes the fields that are set. Command execution can only change while the extension is not assigned, and cannot be switched off while a host reports it kept (osctrld could not remove it). Super admins only.
// @Tags extensions
// @Accept json
// @Produce json
// @Param id path int true "Extension ID"
// @Param request body types.ExtensionUpdateRequest true "Fields to change"
// @Success 200 {object} types.ExtensionView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Extension is assigned, or still on a host that could not remove it"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions/{id} [patch]
func (h *HandlersApi) ExtensionsUpdateHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireExtensionsAdmin(w, r)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return
	}
	var req types.ExtensionUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, extensionJSONMaxBody)).Decode(&req); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	cur, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return
	}
	// ponytail: read-then-write, so a concurrent PATCH of another field can be
	// lost; add a column-level update in pkg/extensions if that matters.
	desc, version := cur.Description, cur.Version
	var fields []string
	if req.Description != nil {
		if len(*req.Description) > extensionDescriptionMax {
			apiErrorResponse(w, fmt.Sprintf("description is longer than %d bytes", extensionDescriptionMax), http.StatusBadRequest, nil)
			return
		}
		desc = *req.Description
		fields = append(fields, "description")
	}
	if req.Version != nil {
		version = *req.Version
		fields = append(fields, "version")
	}
	if req.CommandExecution != nil {
		fields = append(fields, "command_execution")
	}
	if len(fields) == 0 {
		apiErrorResponse(w, "nothing to update", http.StatusBadRequest, nil)
		return
	}
	e, err := h.Extensions.Update(id, desc, version, req.CommandExecution, user)
	if err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("updated extension %s: %s", e.Name, strings.Join(fields, ", ")), utils.GetIP(r))
	view, err := h.extensionView(e.ID)
	if err != nil {
		extensionsError(w, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, view)
}

// ExtensionsDeleteHandler - DELETE Handler to remove an extension
// @Summary Delete an osquery extension
// @Description Removes an extension and its files. Refused while it is assigned to any environment or node, or, for a command-execution extension, while a host reports it kept (osctrld could not remove it). Super admins only.
// @Tags extensions
// @Produce json
// @Param id path int true "Extension ID"
// @Success 204 "No content"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Extension is assigned, or still on a host that could not remove it"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions/{id} [delete]
func (h *HandlersApi) ExtensionsDeleteHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireExtensionsAdmin(w, r)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return
	}
	e, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return
	}
	if err := h.Extensions.Delete(id); err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, "deleted extension "+e.Name, utils.GetIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// ExtensionFilePutHandler - PUT Handler to upload an extension binary
// @Summary Upload an osquery extension file
// @Description Stores or replaces the binary for one platform and arch from the multipart field `file` (at most 64 MiB). Platforms: darwin (amd64, arm64, universal), linux (amd64, arm64), windows (amd64). Super admins only.
// @Tags extensions
// @Accept multipart/form-data
// @Produce json
// @Param id path int true "Extension ID"
// @Param platform path string true "Platform"
// @Param arch path string true "Architecture"
// @Param file formData file true "Extension binary"
// @Success 200 {object} types.ExtensionFileView
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 413 {object} types.ApiErrorResponse "File too large"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions/{id}/files/{platform}/{arch} [put]
func (h *HandlersApi) ExtensionFilePutHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireExtensionsAdmin(w, r)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return
	}
	platform, arch := r.PathValue("platform"), r.PathValue("arch")
	if !extensions.ValidPlatform(platform, arch) {
		apiErrorResponse(w, "unsupported platform or arch", http.StatusBadRequest, nil)
		return
	}
	e, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return
	}
	// PutFile holds a transaction while it reads, so a stalled client must
	// not keep the connection forever.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(extensionUploadTimeout)); err != nil {
		log.Debug().Err(err).Msg("extension upload: no read deadline")
	}
	r.Body = http.MaxBytesReader(w, r.Body, extensionUploadMaxBody)
	// Stream the part straight into PutFile; ParseMultipartForm/FormFile
	// would buffer the whole file first.
	mr, err := r.MultipartReader()
	if err != nil {
		apiErrorResponse(w, "expected a multipart/form-data body", http.StatusBadRequest, err)
		return
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			apiErrorResponse(w, "missing multipart field file", http.StatusBadRequest, nil)
			return
		}
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				extensionsError(w, err)
			} else {
				apiErrorResponse(w, "invalid multipart body", http.StatusBadRequest, err)
			}
			return
		}
		if part.FormName() != "file" {
			continue
		}
		f, err := h.Extensions.PutFile(r.Context(), id, platform, arch, sanitizeFilename(part.FileName()), part, user)
		if err != nil {
			extensionsError(w, err)
			return
		}
		h.AuditLog.SettingsAction(user, fmt.Sprintf("uploaded %s/%s file for extension %s: sha256=%s size=%d", platform, arch, e.Name, f.SHA256, f.Size), utils.GetIP(r))
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toExtensionFileView(*f))
		return
	}
}

// ExtensionFileDeleteHandler - DELETE Handler to remove an extension binary
// @Summary Delete an osquery extension file
// @Description Removes the binary for one platform and arch. Super admins only.
// @Tags extensions
// @Produce json
// @Param id path int true "Extension ID"
// @Param platform path string true "Platform"
// @Param arch path string true "Architecture"
// @Success 204 "No content"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/extensions/{id}/files/{platform}/{arch} [delete]
func (h *HandlersApi) ExtensionFileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.requireExtensionsAdmin(w, r)
	if !ok {
		return
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return
	}
	platform, arch := r.PathValue("platform"), r.PathValue("arch")
	if !extensions.ValidPlatform(platform, arch) {
		apiErrorResponse(w, "unsupported platform or arch", http.StatusBadRequest, nil)
		return
	}
	e, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return
	}
	if err := h.Extensions.DeleteFile(id, platform, arch); err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("deleted %s/%s file for extension %s", platform, arch, e.Name), utils.GetIP(r))
	w.WriteHeader(http.StatusNoContent)
}
