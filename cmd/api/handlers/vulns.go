package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/jmpsec/osctrl/pkg/vulns"
	"gorm.io/gorm"
)

// VulnFindingsResponse is one page of findings.
type VulnFindingsResponse struct {
	Findings []vulns.Finding `json:"findings"`
	Total    int64           `json:"total"`
	Page     int             `json:"page"`
}

// vulnUser returns the authenticated user, or writes 401 or 503 and returns
// ok=false.
func (h *HandlersApi) vulnUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return "", false
	}
	if h.Vulns == nil {
		apiErrorResponse(w, "vulnerability monitoring not enabled", http.StatusServiceUnavailable, nil)
		return "", false
	}
	return ctxVal.(ContextValue)[ctxUser], true
}

// vulnEnvironment resolves {env} and checks the caller may read it, with the
// same check node and posture reads use. It writes the error response itself.
func (h *HandlersApi) vulnEnvironment(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, bool) {
	user, ok := h.vulnUser(w, r)
	if !ok {
		return environments.TLSEnvironment{}, false
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "env required", http.StatusBadRequest, nil)
		return environments.TLSEnvironment{}, false
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return environments.TLSEnvironment{}, false
	}
	if !h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return environments.TLSEnvironment{}, false
	}
	return env, true
}

// VulnFindingsHandler — GET /api/v1/vulnerabilities/{env}/findings
// @Summary List vulnerability findings
// @Description Open findings in an environment by default. Filters: severity, confidence, kev, state (open|resolved|all), package, advisory, page, page_size.
// @Tags vulnerabilities
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param severity query string false "critical|high|medium|low|unknown"
// @Param confidence query string false "confirmed|possible"
// @Param kev query bool false "Only CISA KEV findings"
// @Param state query string false "open|resolved|all"
// @Param package query string false "Package name"
// @Param advisory query string false "Advisory id"
// @Param page query int false "Page (1-based)"
// @Param page_size query int false "Page size (max 500)"
// @Success 200 {object} VulnFindingsResponse
// @Failure 400 {object} types.ApiErrorResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/{env}/findings [get]
func (h *HandlersApi) VulnFindingsHandler(w http.ResponseWriter, r *http.Request) {
	env, ok := h.vulnEnvironment(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	kev, _ := strconv.ParseBool(q.Get("kev"))
	filter := vulns.FindingFilter{
		EnvironmentID: env.ID, Severity: q.Get("severity"), Confidence: q.Get("confidence"),
		KEV: kev, State: q.Get("state"), Package: q.Get("package"), Advisory: q.Get("advisory"),
		Page: page, PageSize: size,
	}
	findings, total, err := h.Vulns.Findings(filter)
	if errors.Is(err, vulns.ErrBadFilter) {
		apiErrorResponse(w, "invalid filter", http.StatusBadRequest, err)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error listing findings", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, VulnFindingsResponse{
		Findings: findings, Total: total, Page: max(page, 1),
	})
}

// VulnSummaryHandler — GET /api/v1/vulnerabilities/{env}/summary
// @Summary Vulnerability summary for an environment
// @Tags vulnerabilities
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} vulns.Summary
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 503 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/{env}/summary [get]
func (h *HandlersApi) VulnSummaryHandler(w http.ResponseWriter, r *http.Request) {
	env, ok := h.vulnEnvironment(w, r)
	if !ok {
		return
	}
	s, err := h.Vulns.Summary(env.ID)
	if err != nil {
		apiErrorResponse(w, "error summarizing findings", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, s)
}

// VulnAdvisoryHandler — GET /api/v1/vulnerabilities/{env}/advisories/{id}
// @Summary One advisory and the nodes it affects in an environment
// @Tags vulnerabilities
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path string true "Advisory id"
// @Success 200 {object} vulns.AdvisoryDetail
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/{env}/advisories/{id} [get]
func (h *HandlersApi) VulnAdvisoryHandler(w http.ResponseWriter, r *http.Request) {
	env, ok := h.vulnEnvironment(w, r)
	if !ok {
		return
	}
	d, err := h.Vulns.Advisory(r.PathValue("id"), env.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		apiErrorResponse(w, "advisory not found", http.StatusNotFound, nil)
		return
	}
	if err != nil {
		apiErrorResponse(w, "error getting advisory", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, d)
}

// VulnNodeHandler — GET /api/v1/nodes/{env}/node/{uuid}/vulnerabilities
// @Summary Vulnerability findings for one node
// @Tags vulnerabilities
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} vulns.NodeReport
// @Failure 403 {object} types.ApiErrorResponse
// @Failure 404 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/vulnerabilities [get]
func (h *HandlersApi) VulnNodeHandler(w http.ResponseWriter, r *http.Request) {
	env, ok := h.vulnEnvironment(w, r)
	if !ok {
		return
	}
	node, err := h.Nodes.GetByUUID(r.PathValue("uuid"))
	if err != nil {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if node.EnvironmentID != env.ID {
		apiErrorResponse(w, "node not in environment", http.StatusForbidden, nil)
		return
	}
	rep, err := h.Vulns.Node(node.UUID, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting node findings", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rep)
}

// VulnFeedsHandler — GET /api/v1/vulnerabilities/feeds
// @Summary Advisory feed sync status
// @Tags vulnerabilities
// @Produce json
// @Success 200 {object} vulns.FeedStatus
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/feeds [get]
func (h *HandlersApi) VulnFeedsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.vulnUser(w, r)
	if !ok {
		return
	}
	if !h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return
	}
	fs, err := h.Vulns.Feeds()
	if err != nil {
		apiErrorResponse(w, "error getting feed status", http.StatusInternalServerError, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, fs)
}

// VulnSyncRequestHandler — POST /api/v1/vulnerabilities/feeds/sync
// @Summary Request an advisory feed sync
// @Description Super-admin only. The worker picks the request up on its next tick (within a minute); the request never downloads anything itself.
// @Tags vulnerabilities
// @Produce json
// @Success 202 {object} types.ApiGenericResponse
// @Failure 403 {object} types.ApiErrorResponse
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/feeds/sync [post]
func (h *HandlersApi) VulnSyncRequestHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := h.vulnUser(w, r)
	if !ok {
		return
	}
	if !h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt by %s", user))
		return
	}
	if err := vulns.RequestSync(h.Vulns.DB, time.Now()); err != nil {
		apiErrorResponse(w, "error requesting sync", http.StatusInternalServerError, err)
		return
	}
	h.AuditLog.SettingsAction(user, "request vulnerability feed sync", utils.GetIP(r))
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusAccepted, types.ApiGenericResponse{Message: "sync requested"})
}

// VulnProfilesHandler — GET /api/v1/vulnerabilities/profiles
// @Summary Inventory schedule profiles for vulnerability monitoring
// @Tags vulnerabilities
// @Produce json
// @Success 200 {array} posture.PostureProfile
// @Security ApiKeyAuth
// @Router /api/v1/vulnerabilities/profiles [get]
func (h *HandlersApi) VulnProfilesHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.vulnUser(w, r); !ok {
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, vulns.Profiles())
}
