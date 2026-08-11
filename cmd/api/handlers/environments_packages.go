package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// validPackageTypes is the set of accepted package type values.
var validPackageTypes = map[string]bool{
	settings.PackageDeb: true,
	settings.PackageRpm: true,
	settings.PackageMsi: true,
	settings.PackagePkg: true,
}

// EnvPackagesHandler - GET Handler to list all enrolling packages for an environment
// @Summary List enrolling packages
// @Description Returns all enrolling packages for an environment.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {array} environments.EnvironmentPackage
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/{env}/packages [get]
func (h *HandlersApi) EnvPackagesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	pkgs, err := h.Envs.GetPackages(env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting packages", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Returned %d packages for env %s", len(pkgs), env.Name)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, pkgs)
}

// EnvPackageAddHandler - POST Handler to add an enrolling package
// @Summary Add enrolling package
// @Description Adds a new enrolling package to an environment.
// @Tags environments
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param request body types.ApiAddPackageRequest true "Request body"
// @Success 201 {object} environments.EnvironmentPackage
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/{env}/packages [post]
func (h *HandlersApi) EnvPackageAddHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var body types.ApiAddPackageRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	if !validPackageTypes[body.Type] {
		apiErrorResponse(w, "invalid package type", http.StatusBadRequest, nil)
		return
	}
	if !environments.ValidArchitectures[body.Arch] {
		apiErrorResponse(w, "invalid architecture", http.StatusBadRequest, nil)
		return
	}
	if body.URL == "" {
		apiErrorResponse(w, "url is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.Envs.AddPackage(env.ID, body.Type, body.Arch, body.URL, body.IsDefault); err != nil {
		apiErrorResponse(w, "error adding package", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.ConfAction(ctx[ctxUser], fmt.Sprintf("add package %s/%s to env %s", body.Type, body.Arch, env.Name), strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Added package %s/%s to env %s", body.Type, body.Arch, env.Name)
	// Fetch the created package to return it.
	pkg, _ := h.Envs.GetPackage(env.ID, body.Type, body.Arch)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, pkg)
}

// EnvPackageRemoveHandler - DELETE Handler to remove an enrolling package
// @Summary Remove enrolling package
// @Description Removes an enrolling package from an environment.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Package ID"
// @Success 204
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/{env}/packages/{id} [delete]
func (h *HandlersApi) EnvPackageRemoveHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	pkgIDStr := r.PathValue("id")
	if pkgIDStr == "" {
		apiErrorResponse(w, "missing package id", http.StatusBadRequest, nil)
		return
	}
	var pkgID uint
	if _, err := fmt.Sscanf(pkgIDStr, "%d", &pkgID); err != nil || pkgID == 0 {
		apiErrorResponse(w, "invalid package id", http.StatusBadRequest, nil)
		return
	}
	if err := h.Envs.RemovePackage(env.ID, pkgID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "package not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error removing package", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.ConfAction(ctx[ctxUser], fmt.Sprintf("remove package %d from env %s", pkgID, env.Name), strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Removed package %d from env %s", pkgID, env.Name)
	w.WriteHeader(http.StatusNoContent)
}

// EnvPackageUpdateHandler - PATCH Handler to update a package URL
// @Summary Update enrolling package URL
// @Description Updates the URL of an existing enrolling package.
// @Tags environments
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Package ID"
// @Param request body types.ApiUpdatePackageRequest true "Request body"
// @Success 200 {object} environments.EnvironmentPackage
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/packages/{env}/{id} [patch]
func (h *HandlersApi) EnvPackageUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "missing environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		if err.Error() == "record not found" {
			apiErrorResponse(w, "environment not found", http.StatusNotFound, err)
		} else {
			apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, err)
		}
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	pkgIDStr := r.PathValue("id")
	if pkgIDStr == "" {
		apiErrorResponse(w, "missing package id", http.StatusBadRequest, nil)
		return
	}
	var pkgID uint
	if _, err := fmt.Sscanf(pkgIDStr, "%d", &pkgID); err != nil || pkgID == 0 {
		apiErrorResponse(w, "invalid package id", http.StatusBadRequest, nil)
		return
	}
	var body types.ApiUpdatePackageRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	if body.URL == "" {
		apiErrorResponse(w, "url is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.Envs.UpdatePackageURL(env.ID, pkgID, body.URL); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "package not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error updating package", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.ConfAction(ctx[ctxUser], fmt.Sprintf("update package %d in env %s", pkgID, env.Name), strings.Split(r.RemoteAddr, ":")[0], env.ID)
	log.Debug().Msgf("Updated package %d in env %s", pkgID, env.Name)
	// Return the updated package.
	var pkg environments.EnvironmentPackage
	h.Envs.DB.Where("environment_id = ? AND id = ?", env.ID, pkgID).First(&pkg)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, pkg)
}
