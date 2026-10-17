package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// toExtensionSummary lists the platforms v has a file for; List returns the
// files ordered by platform.
func toExtensionSummary(v extensions.ExtensionView) types.ExtensionSummary {
	platforms := []string{}
	for _, f := range v.Files {
		if len(platforms) == 0 || platforms[len(platforms)-1] != f.Platform {
			platforms = append(platforms, f.Platform)
		}
	}
	return types.ExtensionSummary{
		ID:               v.ID,
		Name:             v.Name,
		Description:      v.Description,
		Version:          v.Version,
		CommandExecution: v.CommandExecution,
		Platforms:        platforms,
	}
}

// envExtensions builds what the environment runs and the ordinary extensions
// that can be added to it.
func (h *HandlersApi) envExtensions(envID uint) (types.EnvironmentExtensionsResponse, error) {
	resp := types.EnvironmentExtensionsResponse{Assigned: []types.ExtensionSummary{}, Available: []types.ExtensionSummary{}}
	views, err := h.Extensions.List()
	if err != nil {
		return resp, err
	}
	assigned, err := h.Extensions.EnvExtensions(envID)
	if err != nil {
		return resp, err
	}
	isAssigned := make(map[uint]bool, len(assigned))
	for _, e := range assigned {
		isAssigned[e.ID] = true
	}
	for _, v := range views {
		switch {
		case isAssigned[v.ID]:
			resp.Assigned = append(resp.Assigned, toExtensionSummary(v))
		case !v.CommandExecution:
			resp.Available = append(resp.Available, toExtensionSummary(v))
		}
	}
	return resp, nil
}

// envExtensionTarget checks the caller is an admin of the environment and
// resolves the extension in the path.
func (h *HandlersApi) envExtensionTarget(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, *extensions.Extension, string, bool) {
	env, ctx, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return env, nil, "", false
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return env, nil, "", false
	}
	e, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return env, nil, "", false
	}
	return env, e, ctx[ctxUser], true
}

func (h *HandlersApi) serveEnvExtensions(w http.ResponseWriter, envID uint) {
	resp, err := h.envExtensions(envID)
	if err != nil {
		extensionsError(w, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// EnvExtensionsHandler - GET Handler for an environment's extensions
// @Summary Get environment extensions
// @Description Returns the extensions assigned to the environment and the ordinary extensions that can be assigned to it. Command-execution extensions are only assigned to nodes. Environment admins.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Success 200 {object} types.EnvironmentExtensionsResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/extensions/{env} [get]
func (h *HandlersApi) EnvExtensionsHandler(w http.ResponseWriter, r *http.Request) {
	env, _, ok := h.inactivityEnvironment(w, r, users.AdminLevel)
	if !ok {
		return
	}
	h.serveEnvExtensions(w, env.ID)
}

// EnvExtensionAssignHandler - PUT Handler to assign an extension to an environment
// @Summary Assign extension to environment
// @Description Assigns an ordinary extension to every node of the environment. Command-execution extensions are refused with 409. Environment admins.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Extension ID"
// @Success 200 {object} types.EnvironmentExtensionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Command-execution extension"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/extensions/{env}/{id} [put]
func (h *HandlersApi) EnvExtensionAssignHandler(w http.ResponseWriter, r *http.Request) {
	env, e, user, ok := h.envExtensionTarget(w, r)
	if !ok {
		return
	}
	if err := h.Extensions.AssignEnv(env.ID, e.ID, user); err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.EnvAction(user, fmt.Sprintf("assigned extension %s to environment %s", e.Name, env.Name), utils.GetIP(r), env.ID)
	h.serveEnvExtensions(w, env.ID)
}

// EnvExtensionRemoveHandler - DELETE Handler to remove an extension from an environment
// @Summary Remove extension from environment
// @Description Removes an extension from the environment. 404 when it is not assigned to the environment. Environment admins.
// @Tags environments
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param id path int true "Extension ID"
// @Success 200 {object} types.EnvironmentExtensionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/environments/extensions/{env}/{id} [delete]
func (h *HandlersApi) EnvExtensionRemoveHandler(w http.ResponseWriter, r *http.Request) {
	env, e, user, ok := h.envExtensionTarget(w, r)
	if !ok {
		return
	}
	if err := h.Extensions.UnassignEnv(env.ID, e.ID); err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.EnvAction(user, fmt.Sprintf("removed extension %s from environment %s", e.Name, env.Name), utils.GetIP(r), env.ID)
	h.serveEnvExtensions(w, env.ID)
}

// nodeExtensions builds the node view. Like osctrl-tls, it only counts
// assignments and statuses recorded in the node's current environment.
func (h *HandlersApi) nodeExtensions(env environments.TLSEnvironment, node nodes.OsqueryNode, superAdmin bool) (types.NodeExtensionsResponse, error) {
	resp := types.NodeExtensionsResponse{
		Effective:   []types.NodeExtensionEffective{},
		Assignments: []types.NodeExtensionAssignment{},
		Status:      []types.NodeExtensionStatusView{},
	}
	views, err := h.Extensions.List()
	if err != nil {
		return resp, err
	}
	envExts, err := h.Extensions.EnvExtensions(env.ID)
	if err != nil {
		return resp, err
	}
	rows, err := h.Extensions.NodeAssignments(node.UUID)
	if err != nil {
		return resp, err
	}
	statuses, err := h.Extensions.NodeStatuses(node.UUID)
	if err != nil {
		return resp, err
	}
	byID := make(map[uint]types.ExtensionSummary, len(views))
	for _, v := range views {
		byID[v.ID] = toExtensionSummary(v)
	}
	platform := nodes.NormalizePlatformBucket(strings.ToLower(node.Platform))
	effective := func(s types.ExtensionSummary, source string) {
		resp.Effective = append(resp.Effective, types.NodeExtensionEffective{
			Name:             s.Name,
			Source:           source,
			CommandExecution: s.CommandExecution,
			Platforms:        s.Platforms,
			Available:        utils.Contains(s.Platforms, platform),
		})
	}
	for _, e := range envExts {
		if s := byID[e.ID]; !s.CommandExecution {
			effective(s, "environment")
		}
	}
	now := time.Now()
	// unexpired names the command-execution extensions this node should run
	unexpired := map[string]bool{}
	for _, a := range rows {
		if a.EnvironmentID != env.ID {
			continue
		}
		s := byID[a.ExtensionID]
		if !a.Expired(now) {
			unexpired[s.Name] = true
		}
		resp.Assignments = append(resp.Assignments, types.NodeExtensionAssignment{
			ExtensionID: a.ExtensionID,
			Name:        s.Name,
			ExpiresAt:   a.ExpiresAt,
			Expired:     a.Expired(now),
			CreatedBy:   a.CreatedBy,
			CreatedAt:   a.CreatedAt,
		})
		if s.CommandExecution && !a.Expired(now) {
			effective(s, "host")
		}
	}
	sort.Slice(resp.Effective, func(i, j int) bool { return resp.Effective[i].Name < resp.Effective[j].Name })
	cmdExec := map[string]bool{}
	for _, v := range views {
		cmdExec[v.Name] = v.CommandExecution
	}
	for _, st := range statuses {
		if st.EnvironmentID == env.ID {
			resp.Status = append(resp.Status, types.NodeExtensionStatusView{
				Name: st.Name, SHA256: st.SHA256, Result: st.Result, Error: st.Error, At: st.At, ReportedAt: st.ReportedAt,
				// osctrld reports a failed removal as kept; a later removed
				// replaces it. Any other result is not evidence it is still there.
				Lingering: cmdExec[st.Name] && st.Result == extensions.ResultKept && !unexpired[st.Name],
			})
		}
	}
	if superAdmin {
		resp.Library = []types.ExtensionSummary{}
		for _, v := range views {
			if v.CommandExecution {
				resp.Library = append(resp.Library, byID[v.ID])
			}
		}
	}
	return resp, nil
}

func (h *HandlersApi) isSuperAdmin(r *http.Request, user string) bool {
	return h.Users.CheckPermissionsContext(r.Context(), user, users.AdminLevel, users.NoEnvironment)
}

func (h *HandlersApi) serveNodeExtensions(w http.ResponseWriter, env environments.TLSEnvironment, node nodes.OsqueryNode, superAdmin bool) {
	resp, err := h.nodeExtensions(env, node, superAdmin)
	if err != nil {
		extensionsError(w, err)
		return
	}
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// nodeExtensionTarget resolves the node as an environment admin, then
// requires a super admin and resolves the extension in the path.
func (h *HandlersApi) nodeExtensionTarget(w http.ResponseWriter, r *http.Request) (environments.TLSEnvironment, nodes.OsqueryNode, *extensions.Extension, string, bool) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return env, node, nil, "", false
	}
	if !h.isSuperAdmin(r, user) {
		h.denyEnv(w, r, ContextValue{ctxUser: user}, env.ID, "command-execution extensions require a super admin")
		return env, node, nil, "", false
	}
	id, err := parseAlertID(r, "id")
	if err != nil {
		apiErrorResponse(w, "invalid extension id", http.StatusBadRequest, err)
		return env, node, nil, "", false
	}
	e, err := h.Extensions.Get(id)
	if err != nil {
		extensionsError(w, err)
		return env, node, nil, "", false
	}
	return env, node, e, user, true
}

// decodeNodeExtensionExpiry reads a body that is exactly one JSON object
// with the expires_at key. Missing expiry must not mean "never": a misspelled
// key would otherwise grant command execution without expiry, so only an
// explicit null does.
func decodeNodeExtensionExpiry(w http.ResponseWriter, r *http.Request) (*time.Time, error) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, extensionJSONMaxBody))
	var body map[string]json.RawMessage
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON object")
	}
	raw, ok := body["expires_at"]
	if !ok || len(body) != 1 {
		return nil, fmt.Errorf("want only the expires_at key")
	}
	var expiresAt *time.Time
	if err := json.Unmarshal(raw, &expiresAt); err != nil {
		return nil, err
	}
	return expiresAt, nil
}

// NodeExtensionsHandler - GET Handler for a node's extensions
// @Summary Get node extensions
// @Description Returns the extensions the node should run, its command-execution assignments and the last status its osctrld reported. Status fields other than reported_at and lingering come from the host and are untrusted. lingering marks a command-execution extension the node has no unexpired assignment for that osctrld reports as kept, i.e. could not remove. library, the command-execution extensions that can be assigned, is null unless the caller is a super admin.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Success 200 {object} types.NodeExtensionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/extensions [get]
func (h *HandlersApi) NodeExtensionsHandler(w http.ResponseWriter, r *http.Request) {
	env, node, user, ok := h.nodeConfigTarget(w, r)
	if !ok {
		return
	}
	h.serveNodeExtensions(w, env, node, h.isSuperAdmin(r, user))
}

// NodeExtensionAssignHandler - PUT Handler to assign a command-execution extension to a node
// @Summary Assign command-execution extension to node
// @Description Allows command execution on the node through the extension until expires_at. The body must be exactly {"expires_at": ...}: a future RFC 3339 time, or an explicit null for no expiry. A missing expires_at, any other key or trailing data is refused with 400. Ordinary extensions are refused with 409. Super admins only.
// @Tags nodes
// @Accept json
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param id path int true "Extension ID"
// @Param request body types.NodeExtensionAssignRequest true "Expiry"
// @Success 200 {object} types.NodeExtensionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Not a command-execution extension"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/extensions/{id} [put]
func (h *HandlersApi) NodeExtensionAssignHandler(w http.ResponseWriter, r *http.Request) {
	env, node, e, user, ok := h.nodeExtensionTarget(w, r)
	if !ok {
		return
	}
	expiresAt, err := decodeNodeExtensionExpiry(w, r)
	if err != nil {
		apiErrorResponse(w, `body must be exactly {"expires_at": <future RFC 3339 time or null>}`, http.StatusBadRequest, err)
		return
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		apiErrorResponse(w, "expires_at must be in the future", http.StatusBadRequest, nil)
		return
	}
	// pkg/extensions takes no context, so the write already outlives a
	// cancelled request.
	if _, err := h.Extensions.AssignNode(node.UUID, env.ID, e.ID, expiresAt, user); err != nil {
		extensionsError(w, err)
		return
	}
	expires := "never"
	if expiresAt != nil {
		expires = expiresAt.UTC().Format(time.RFC3339)
	}
	h.AuditLog.NodeAction(user, fmt.Sprintf("allowed command execution on node %s via extension %s (expires %s)", node.UUID, e.Name, expires), utils.GetIP(r), env.ID)
	h.serveNodeExtensions(w, env, node, true)
}

// NodeExtensionRemoveHandler - DELETE Handler to remove a command-execution extension from a node
// @Summary Remove command-execution extension from node
// @Description Removes the extension's assignment to the node. 404 when the node has no assignment of that extension. Super admins only.
// @Tags nodes
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param id path int true "Extension ID"
// @Success 200 {object} types.NodeExtensionsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @Router /api/v1/nodes/{env}/node/{uuid}/extensions/{id} [delete]
func (h *HandlersApi) NodeExtensionRemoveHandler(w http.ResponseWriter, r *http.Request) {
	env, node, e, user, ok := h.nodeExtensionTarget(w, r)
	if !ok {
		return
	}
	if err := h.Extensions.UnassignNode(node.UUID, e.ID); err != nil {
		extensionsError(w, err)
		return
	}
	h.AuditLog.NodeAction(user, fmt.Sprintf("removed command execution extension %s from node %s", e.Name, node.UUID), utils.GetIP(r), env.ID)
	h.serveNodeExtensions(w, env, node, true)
}
