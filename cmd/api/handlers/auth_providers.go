package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/authproviders"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const authProviderCommandTTL = 2 * time.Minute

type authProviderDTO struct {
	ID        uint            `json:"id"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Enabled   bool            `json:"enabled"`
	Config    json.RawMessage `json:"config"`
	Source    string          `json:"source"`
	Info      string          `json:"info"`
}

func toAuthProviderDTO(p authproviders.AuthProvider, reveal bool) authProviderDTO {
	cfg := p.Config
	if !reveal {
		cfg = authproviders.RedactedConfig(p.Type, p.Config)
	}
	return authProviderDTO{
		ID:        p.ID,
		CreatedAt: p.CreatedAt.Format(time.RFC3339),
		UpdatedAt: p.UpdatedAt.Format(time.RFC3339),
		Name:      p.Name,
		Type:      p.Type,
		Enabled:   p.Enabled,
		Config:    json.RawMessage(cfg),
		Source:    p.Source,
		Info:      p.Info,
	}
}

func (h *HandlersApi) requireAuthProvidersAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use auth-providers API by user %s", ctx[ctxUser]))
		return "", false
	}
	return ctx[ctxUser], true
}

// AuthProvidersListHandler — GET /api/v1/auth-providers
func (h *HandlersApi) AuthProvidersListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	rows, err := h.AuthProviderMgr.List()
	if err != nil {
		apiErrorResponse(w, "error listing auth providers", http.StatusInternalServerError, err)
		return
	}
	reveal := r.URL.Query().Get("reveal") == "1"
	out := make([]authProviderDTO, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAuthProviderDTO(row, reveal))
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// AuthProvidersTypesHandler — GET /api/v1/auth-providers/types
func (h *HandlersApi) AuthProvidersTypesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	if _, ok := h.requireAuthProvidersAdmin(w, r); !ok {
		return
	}
	specs := make([]types.LogSinkTypeSpec, 0, len(authproviders.Registry))
	for _, typ := range authproviders.SupportedTypes() {
		spec := authproviders.Registry[typ]
		fields := make([]types.LogSinkFieldSpec, 0, len(spec.Fields))
		for _, f := range spec.Fields {
			fields = append(fields, types.LogSinkFieldSpec{
				Name: f.Name, Label: f.Label, Type: string(f.Type),
				Required: f.Required, Secret: f.Secret,
				Placeholder: f.Placeholder, Help: f.Help,
				Options: f.Options, Default: f.Default,
			})
		}
		specs = append(specs, types.LogSinkTypeSpec{
			Type: spec.Type, Description: spec.Description,
			HasSecret: spec.HasSecret, SecretFields: spec.SecretFields,
			Fields: fields,
		})
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, specs)
}

// AuthProvidersGetHandler — GET /api/v1/auth-providers/{id}
func (h *HandlersApi) AuthProvidersGetHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseAuthProviderID(r)
	if err != nil {
		apiErrorResponse(w, "invalid provider id", http.StatusBadRequest, err)
		return
	}
	row, err := h.AuthProviderMgr.Get(id)
	if err != nil {
		if errors.Is(err, authproviders.ErrProviderNotFound) {
			apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting auth provider", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.Visit(user, r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAuthProviderDTO(row, r.URL.Query().Get("reveal") == "1"))
}

// AuthProvidersCreateHandler — POST /api/v1/auth-providers
func (h *HandlersApi) AuthProvidersCreateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	var body struct {
		Name    string          `json:"name"`
		Type    string          `json:"type"`
		Enabled bool            `json:"enabled"`
		Config  json.RawMessage `json:"config"`
		Info    string          `json:"info,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	row, err := h.AuthProviderMgr.Create(body.Name, body.Type, body.Enabled, string(body.Config), body.Info)
	if err != nil {
		respondAuthProviderErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("created auth provider %q (type %s)", row.Name, row.Type), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, toAuthProviderDTO(row, true))
}

// AuthProvidersUpdateHandler — PUT /api/v1/auth-providers/{id}
func (h *HandlersApi) AuthProvidersUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseAuthProviderID(r)
	if err != nil {
		apiErrorResponse(w, "invalid provider id", http.StatusBadRequest, err)
		return
	}
	var body struct {
		Name    string          `json:"name"`
		Type    string          `json:"type"`
		Enabled bool            `json:"enabled"`
		Config  json.RawMessage `json:"config"`
		Info    string          `json:"info,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	prev, err := h.AuthProviderMgr.Get(id)
	if err != nil {
		if errors.Is(err, authproviders.ErrProviderNotFound) {
			apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting auth provider", http.StatusInternalServerError, err)
		return
	}
	merged, err := authproviders.MergeSecrets(prev.Type, prev.Config, string(body.Config))
	if err != nil {
		apiErrorResponse(w, "error merging provider secrets", http.StatusBadRequest, err)
		return
	}
	row, err := h.AuthProviderMgr.Update(id, body.Name, body.Type, body.Enabled, merged, body.Info)
	if err != nil {
		respondAuthProviderErr(w, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("updated auth provider %q (type %s)", row.Name, row.Type), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAuthProviderDTO(row, true))
}

// AuthProvidersDeleteHandler — DELETE /api/v1/auth-providers/{id}
func (h *HandlersApi) AuthProvidersDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseAuthProviderID(r)
	if err != nil {
		apiErrorResponse(w, "invalid provider id", http.StatusBadRequest, err)
		return
	}
	if err := h.AuthProviderMgr.Delete(id); err != nil {
		if errors.Is(err, authproviders.ErrProviderNotFound) {
			apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error deleting auth provider", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("deleted auth provider %d", id), strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusNoContent)
}

// AuthProvidersRevertHandler — POST /api/v1/auth-providers/{id}/revert
func (h *HandlersApi) AuthProvidersRevertHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.AuthProviderMgr == nil {
		apiErrorResponse(w, "auth providers not initialized", http.StatusInternalServerError, nil)
		return
	}
	id, err := parseAuthProviderID(r)
	if err != nil {
		apiErrorResponse(w, "invalid provider id", http.StatusBadRequest, err)
		return
	}
	if err := h.AuthProviderMgr.RevertToService(id); err != nil {
		if errors.Is(err, authproviders.ErrProviderNotFound) {
			apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error reverting auth provider", http.StatusInternalServerError, err)
		return
	}
	row, err := h.AuthProviderMgr.Get(id)
	if err != nil {
		apiErrorResponse(w, "error getting reverted auth provider", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("reverted auth provider %q to service config", row.Name), strings.Split(r.RemoteAddr, ":")[0])
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, toAuthProviderDTO(row, false))
}

// AuthProvidersTestHandler — POST /api/v1/auth-providers/test
func (h *HandlersApi) AuthProvidersTestHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	if _, ok := h.requireAuthProvidersAdmin(w, r); !ok {
		return
	}
	var body struct {
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	typ := strings.ToLower(strings.TrimSpace(body.Type))
	spec, ok := authproviders.Registry[typ]
	if !ok {
		apiErrorResponse(w, "invalid provider type", http.StatusBadRequest, nil)
		return
	}
	decoded, err := spec.Decode(body.Config)
	if err != nil {
		apiErrorResponse(w, "invalid config", http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, err = spec.Build(decoded, ctx)
	if err != nil {
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, map[string]any{
		"ok": true,
	})
}

// AuthProvidersFetchMetadataHandler — POST /api/v1/auth-providers/fetch-metadata
//
// Fetches the IdP metadata XML from the given URL and returns it as
// text. The operator can then review it before saving it into the
// IDPMetadataXML field of a SAML provider. Saves a round-trip to the
// IdP's metadata URL from the browser (which may be on a different
// network than the server) and avoids CORS issues.
//
// @Summary Fetch IdP metadata XML
// @Description Fetches the SAML IdP metadata document from the given URL and returns the XML.
// @Tags auth-providers
// @Accept json
// @Produce json
// @Param request body object true "{ \"url\": \"https://idp/metadata\" }"
// @Success 200 {object} object "{ \"xml\": \"<EntityDescriptor ...>\" }"
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 502 {object} types.ApiErrorResponse "Fetch failed"
// @Security ApiKeyAuth
// @Router /api/v1/auth-providers/fetch-metadata [post]
func (h *HandlersApi) AuthProvidersFetchMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	if _, ok := h.requireAuthProvidersAdmin(w, r); !ok {
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErrorResponse(w, "error parsing request body", http.StatusBadRequest, err)
		return
	}
	metadataURL := strings.TrimSpace(body.URL)
	if metadataURL == "" {
		apiErrorResponse(w, "url is required", http.StatusBadRequest, nil)
		return
	}
	u, err := url.Parse(metadataURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		apiErrorResponse(w, "url must be a valid http(s) URL", http.StatusBadRequest, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		apiErrorResponse(w, "error building request", http.StatusBadRequest, err)
		return
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		apiErrorResponse(w, "error fetching metadata", http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		apiErrorResponse(w, fmt.Sprintf("IdP returned HTTP %d", resp.StatusCode), http.StatusBadGateway, nil)
		return
	}
	// Cap at 1 MiB — same limit as the SAML provider's own fetch.
	xmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		apiErrorResponse(w, "error reading metadata", http.StatusBadGateway, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, map[string]any{
		"xml": string(xmlBytes),
	})
}

// AuthProvidersApplyHandler — POST /api/v1/auth-providers/apply
func (h *HandlersApi) AuthProvidersApplyHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	user, ok := h.requireAuthProvidersAdmin(w, r)
	if !ok {
		return
	}
	if h.ServiceCommands == nil {
		apiErrorResponse(w, "service commands not available", http.StatusServiceUnavailable, nil)
		return
	}
	cmd, err := h.ServiceCommands.Request(config.ServiceTLS, servicecommands.ActionReloadAuthProviders, user, strings.Split(r.RemoteAddr, ":")[0], authProviderCommandTTL)
	if err != nil {
		apiErrorResponse(w, "error requesting auth providers reload", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, fmt.Sprintf("apply auth-providers reload command %s", cmd.CommandID), strings.Split(r.RemoteAddr, ":")[0])
	log.Info().Str("command", cmd.CommandID).Msgf("Auth providers reload requested by %s", user)
	resp := serviceCommandResponse(cmd)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ServiceConfigApplyResponse{
		Service: config.ServiceAPI,
		Message: "Reload requested. osctrl-api will rebuild its auth provider registry after consuming the service command.",
		Command: &resp,
	})
}

func parseAuthProviderID(r *http.Request) (uint, error) {
	v := r.PathValue("id")
	if v == "" {
		return 0, fmt.Errorf("missing id")
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid id: %w", err)
	}
	return uint(n), nil
}

func respondAuthProviderErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authproviders.ErrInvalidProviderType):
		apiErrorResponse(w, "invalid auth provider type", http.StatusBadRequest, err)
	case errors.Is(err, authproviders.ErrInvalidProviderConfig):
		apiErrorResponse(w, "invalid auth provider configuration", http.StatusBadRequest, err)
	case errors.Is(err, authproviders.ErrProviderNotFound):
		apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
	case errors.Is(err, gorm.ErrRecordNotFound):
		apiErrorResponse(w, "auth provider not found", http.StatusNotFound, err)
	default:
		apiErrorResponse(w, "error", http.StatusInternalServerError, err)
	}
}
