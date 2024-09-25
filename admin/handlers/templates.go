package handlers

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
)

// TemplateFiles for building UI layout
type TemplateFiles struct {
	filepaths []string
}

// Valid values for download target
var validTarget = map[string]bool{
	settings.DownloadSecret:       true,
	settings.DownloadCert:         true,
	settings.DownloadFlags:        true,
	settings.DownloadFlagsLinux:   true,
	settings.DownloadFlagsMac:     true,
	settings.DownloadFlagsWin:     true,
	settings.DownloadFlagsFreeBSD: true,
}

// TemplateMetadata - Helper to prepare template metadata
// TODO until a better implementation, all users are admin
func (h *HandlersAdmin) TemplateMetadata(ctx sessions.ContextValue, version string) TemplateMetadata {
	return TemplateMetadata{
		Username:       ctx[sessions.CtxUser],
		Level:          "admin",
		CSRFToken:      ctx[sessions.CtxCSRF],
		Service:        "osctrl-admin",
		Version:        version,
		TLSDebug:       h.Settings.DebugService(settings.ServiceTLS),
		AdminDebug:     h.Settings.DebugService(settings.ServiceAdmin),
		APIDebug:       h.Settings.DebugService(settings.ServiceAPI),
		AdminDebugHTTP: h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID),
		APIDebugHTTP:   h.Settings.DebugHTTP(settings.ServiceAPI, settings.NoEnvironmentID),
	}
}

// NewTemplateFiles defines based on layout and default static pages
func (h *HandlersAdmin) NewTemplateFiles(base string, layoutFilename string) *TemplateFiles {
	paths := []string{
		base + "/" + layoutFilename,
		base + "/components/page-head-" + h.StaticLocation + ".html",
		base + "/components/page-js-" + h.StaticLocation + ".html",
		base + "/components/page-header.html",
		base + "/components/page-aside-left.html",
		base + "/components/page-aside-right.html",
		base + "/components/page-modals.html",
	}
	tf := TemplateFiles{filepaths: paths}
	return &tf
}

// LoginHandler for login page for GET requests
func (h *HandlersAdmin) LoginHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Prepare template
	t, err := template.ParseFiles(
		h.TemplatesFolder+"/login.html",
		h.TemplatesFolder+"/components/page-head-"+h.StaticLocation+".html",
		h.TemplatesFolder+"/components/page-js-"+h.StaticLocation+".html")
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting login template")
		return
	}
	// Prepare template data
	templateData := LoginTemplateData{
		Title:   "Login to osctrl",
		Project: "osctrl",
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Login template served")
	}
	h.Inc(metricAdminOK)
}

// EnvironmentHandler for environment view of the table
func (h *HandlersAdmin) EnvironmentHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricTokenErr)
		return
	}
	// Extract target
	// FIXME verify target
	target := r.PathValue("target")
	if target == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting target")
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "table.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all tags
	tags, err := h.Tags.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:        "Nodes in " + env.Name,
		EnvUUID:      env.UUID,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Selector:     "environment",
		SelectorName: env.Name,
		Target:       target,
		Tags:         tags,
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Environment table template served")
	}
	h.Inc(metricAdminOK)
}

// PlatformHandler for platform view of the table
func (h *HandlersAdmin) PlatformHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract platform
	// FIXME verify platform
	platform := r.PathValue("platform")
	if platform == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting platform")
		return
	}
	// Extract target
	// FIXME verify target
	target := r.PathValue("target")
	if target == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting target")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricTokenErr)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		h.TemplatesFolder+"/table.html",
		h.TemplatesFolder+"/components/page-head-"+h.StaticLocation+".html",
		h.TemplatesFolder+"/components/page-js-"+h.StaticLocation+".html",
		h.TemplatesFolder+"/components/page-aside-right.html",
		h.TemplatesFolder+"/components/page-aside-left.html",
		h.TemplatesFolder+"/components/page-header.html",
		h.TemplatesFolder+"/components/page-modals.html")
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all tags
	tags, err := h.Tags.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := TableTemplateData{
		Title:        "Nodes in " + platform,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Selector:     "platform",
		SelectorName: platform,
		Target:       target,
		Tags:         tags,
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Platform table template served")
	}
	h.Inc(metricAdminOK)
}

// QueryRunGETHandler for GET requests to run queries
func (h *HandlersAdmin) QueryRunGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	t, err := template.ParseFiles(
		h.TemplatesFolder+"/queries-run.html",
		h.TemplatesFolder+"/components/page-head-"+h.StaticLocation+".html",
		h.TemplatesFolder+"/components/page-js-"+h.StaticLocation+".html",
		h.TemplatesFolder+"/components/page-aside-right.html",
		h.TemplatesFolder+"/components/page-aside-left.html",
		h.TemplatesFolder+"/components/page-header.html",
		h.TemplatesFolder+"/components/page-modals.html")
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get all nodes
	nodes, err := h.Nodes.Gets("active", h.Settings.InactiveHours(settings.NoEnvironmentID))
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting all nodes")
		return
	}
	// Convert to list of UUIDs and Hosts
	// FIXME if the number of nodes is big, this may cause issues loading the page
	var uuids, hosts []string
	for _, n := range nodes {
		uuids = append(uuids, n.UUID)
		hosts = append(hosts, n.Localname)
	}
	// Prepare template data
	templateData := QueryRunTemplateData{
		Title:         "Query osquery Nodes in <b>" + env.Name + "</b>",
		EnvUUID:       env.UUID,
		Metadata:      h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments:  h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:     platforms,
		UUIDs:         uuids,
		Hosts:         hosts,
		Tables:        h.OsqueryTables,
		TablesVersion: h.OsqueryVersion,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Query run template served")
	}
	h.Inc(metricAdminOK)
}

// QueryListGETHandler for GET requests to queries
func (h *HandlersAdmin) QueryListGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "queries.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := QueryTableTemplateData{
		Title:        "All on-demand queries",
		EnvUUID:      env.UUID,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		Target:       "all",
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Query list template served")
	}
	h.Inc(metricAdminOK)
}

// SavedQueriesGETHandler for GET requests to queries
func (h *HandlersAdmin) SavedQueriesGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "saved.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := SavedQueriesTemplateData{
		Title:        "Saved queries in <b>" + env.Name + "</b>",
		EnvUUID:      env.UUID,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		Target:       "saved",
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Query list template served")
	}
	h.Inc(metricAdminOK)
}

// CarvesRunGETHandler for GET requests to run file carves
func (h *HandlersAdmin) CarvesRunGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "carves-run.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get all nodes
	nodes, err := h.Nodes.Gets("active", h.Settings.InactiveHours(settings.NoEnvironmentID))
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting all nodes")
		return
	}
	// Convert to list of UUIDs and Hosts
	// FIXME if the number of nodes is big, this may cause issues loading the page
	var uuids, hosts []string
	for _, n := range nodes {
		uuids = append(uuids, n.UUID)
		hosts = append(hosts, n.Localname)
	}
	// Prepare template data
	templateData := CarvesRunTemplateData{
		Title:         "Query osquery Nodes in <b>" + env.Name + "</b>",
		EnvUUID:       env.UUID,
		Metadata:      h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments:  h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:     platforms,
		UUIDs:         uuids,
		Hosts:         hosts,
		Tables:        h.OsqueryTables,
		TablesVersion: h.OsqueryVersion,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Query run template served")
	}
	h.Inc(metricAdminOK)
}

// CarvesListGETHandler for GET requests to carves
func (h *HandlersAdmin) CarvesListGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "carves.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := CarvesTableTemplateData{
		Title:        "Carved files in <b>" + env.Name + "</b>",
		EnvUUID:      env.UUID,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		Target:       "all",
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Carve list template served")
	}
	h.Inc(metricAdminOK)
}

// QueryLogsHandler for GET requests to see query results by name
func (h *HandlersAdmin) QueryLogsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.QueryLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting name")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"queryResultLink": h.queryResultLink,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "queries-logs.html").filepaths
	t, err := template.New("queries-logs.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get query by name
	query, err := h.Queries.Get(name, env.ID)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting query")
		return
	}
	// Get query targets
	targets, err := h.Queries.GetTargets(name)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting targets")
		return
	}
	leftMetadata := AsideLeftMetadata{
		EnvUUID:   env.UUID,
		Query:     true,
		QueryName: query.Name,
	}
	// Prepare template data
	templateData := QueryLogsTemplateData{
		Title:         "Query logs " + query.Name,
		EnvUUID:       env.UUID,
		Metadata:      h.TemplateMetadata(ctx, h.ServiceVersion),
		LeftMetadata:  leftMetadata,
		Environments:  h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:     platforms,
		Query:         query,
		QueryTargets:  targets,
		ServiceConfig: *h.AdminConfig,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Query logs template served")
	}
	h.Inc(metricAdminOK)
}

// CarvesDetailsHandler for GET requests to see carves details by name
func (h *HandlersAdmin) CarvesDetailsHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		log.Info().Msg("environment is missing")
		h.Inc(metricAdminErr)
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		log.Err(err).Msgf("error getting environment %s", envVar)
		h.Inc(metricAdminErr)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.CarveLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Extract name
	name := r.PathValue("name")
	if name == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting name")
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "carves-details.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get query by name
	query, err := h.Queries.Get(name, env.ID)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting query")
		return
	}
	// Get query targets
	targets, err := h.Queries.GetTargets(name)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting targets")
		return
	}
	// Get carves for this query
	queryCarves, err := h.Carves.GetByQuery(name, env.ID)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting carve")
		return
	}
	// Get carve blocks by carve
	blocks := make(map[string][]carves.CarvedBlock)
	for _, c := range queryCarves {
		bs, err := h.Carves.GetBlocks(c.SessionID)
		if err != nil {
			h.Inc(metricAdminErr)
			log.Err(err).Msg("error getting carve blocks")
			break
		}
		blocks[c.SessionID] = bs
	}
	leftMetadata := AsideLeftMetadata{
		EnvUUID:   env.UUID,
		Carve:     true,
		CarveName: query.Name,
	}
	// Prepare template data
	templateData := CarvesDetailsTemplateData{
		Title:        "Carve details " + query.Name,
		EnvUUID:      env.UUID,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		LeftMetadata: leftMetadata,
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		Query:        query,
		QueryTargets: targets,
		Carves:       queryCarves,
		CarveBlocks:  blocks,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Carve details template served")
	}
	h.Inc(metricAdminOK)
}

// ConfGETHandler for GET requests for /conf
func (h *HandlersAdmin) ConfGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "conf.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting conf template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := ConfTemplateData{
		Title:        env.Name + " Configuration",
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environment:  env,
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Conf template served")
	}
	h.Inc(metricAdminOK)
}

// EnrollGETHandler for GET requests for /enroll
func (h *HandlersAdmin) EnrollGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "enroll.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting enroll template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	shellQuickAdd, _ := environments.QuickAddOneLinerShell((env.Certificate != ""), env)
	powershellQuickAdd, _ := environments.QuickAddOneLinerPowershell((env.Certificate != ""), env)
	shellQuickRemove, _ := environments.QuickRemoveOneLinerShell((env.Certificate != ""), env)
	powershellQuickRemove, _ := environments.QuickRemoveOneLinerPowershell((env.Certificate != ""), env)
	templateData := EnrollTemplateData{
		Title:                 env.Name + " Enroll",
		Metadata:              h.TemplateMetadata(ctx, h.ServiceVersion),
		EnvName:               env.Name,
		EnvUUID:               env.UUID,
		OnelinerExpiration:    h.Settings.OnelinerExpiration(settings.NoEnvironmentID),
		EnrollExpiry:          strings.ToUpper(utils.InFutureTime(env.EnrollExpire)),
		EnrollExpired:         environments.IsItExpired(env.EnrollExpire),
		DisplayPackages:       (env.DebPackage != "" || env.RpmPackage != "" || env.MsiPackage != "" || env.PkgPackage != ""),
		DebPackage:            env.DebPackage,
		DebPackageURL:         environments.PackageDownloadURL(env, env.DebPackage),
		RpmPackage:            env.RpmPackage,
		RpmPackageURL:         environments.PackageDownloadURL(env, env.RpmPackage),
		MsiPackage:            env.MsiPackage,
		MsiPackageURL:         environments.PackageDownloadURL(env, env.MsiPackage),
		PkgPackage:            env.PkgPackage,
		PkgPackageURL:         environments.PackageDownloadURL(env, env.PkgPackage),
		RemoveExpiry:          strings.ToUpper(utils.InFutureTime(env.RemoveExpire)),
		RemoveExpired:         environments.IsItExpired(env.RemoveExpire),
		QuickAddShell:         shellQuickAdd,
		QuickRemoveShell:      shellQuickRemove,
		QuickAddPowershell:    powershellQuickAdd,
		QuickRemovePowershell: powershellQuickRemove,
		Secret:                env.Secret,
		Flags:                 env.Flags,
		Certificate:           env.Certificate,
		Environments:          h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:             platforms,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Enroll template served")
	}
	h.Inc(metricAdminOK)
}

// EnrollGETHandler for GET requests for /enroll
func (h *HandlersAdmin) EnrollDownloadHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract environment
	envVar := r.PathValue("env")
	if envVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting environment")
		return
	}
	// Get environment
	env, err := h.Envs.Get(envVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get download target
	targetVar := r.PathValue("target")
	if targetVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting download target")
		return
	}
	// Check if requested download target is valid
	if !validTarget[targetVar] {
		h.Inc(metricAdminErr)
		log.Info().Msgf("invalid download target: %s", targetVar)
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare download
	var toDownload []byte
	var fName, description string
	switch targetVar {
	case settings.DownloadSecret:
		toDownload = []byte(env.Secret)
		description = "osctrl secret for " + env.Name
		fName = "osctrl-" + env.Name + ".secret"
	case settings.DownloadCert:
		toDownload = []byte(env.Certificate)
		description = "osctrl certificate for " + env.Name
		fName = "osctrl-" + env.Name + ".crt"
	case settings.DownloadFlags:
		toDownload = []byte(env.Flags)
		description = "osctrl flags for " + env.Name
		fName = "osctrl-" + env.Name + ".flags"
	case settings.DownloadFlagsMac:
		osxPath := "/private/var/osquery"
		toDownload = []byte(h.generateFlags(env.Flags, osxPath+"/osctrl-"+env.Name+".secret", osxPath+"/osctrl-"+env.Name+".crt"))
		description = "osctrl flags for " + env.Name + " (macOS)"
		fName = "osctrl-" + env.Name + ".flags"
	case settings.DownloadFlagsWin:
		winPath := "C:\\Program Files\\osquery"
		toDownload = []byte(h.generateFlags(env.Flags, winPath+"\\osctrl-"+env.Name+".secret", winPath+"\\osctrl-"+env.Name+".crt"))
		description = "osctrl flags for " + env.Name + " (Windows)"
		fName = "osctrl-" + env.Name + ".flags"
	case settings.DownloadFlagsLinux:
		lnxPath := "/etc/osquery"
		toDownload = []byte(h.generateFlags(env.Flags, lnxPath+"/osctrl-"+env.Name+".secret", lnxPath+"/osctrl-"+env.Name+".crt"))
		description = "osctrl flags for " + env.Name + " (Linux)"
		fName = "osctrl-" + env.Name + ".flags"
	case settings.DownloadFlagsFreeBSD:
		bsdPath := "/usr/local/etc"
		toDownload = []byte(h.generateFlags(env.Flags, bsdPath+"/osctrl-"+env.Name+".secret", bsdPath+"/osctrl-"+env.Name+".crt"))
		description = "osctrl flags for " + env.Name + " (FreeBSD)"
		fName = "osctrl-" + env.Name + ".flags"
	}
	utils.HTTPDownload(w, description, fName, int64(len(toDownload)))
	w.WriteHeader(http.StatusOK)
	h.Inc(metricAdminOK)
	_, _ = io.Copy(w, bytes.NewReader(toDownload))
	h.Inc(metricAdminOK)
}

// NodeHandler for node view
func (h *HandlersAdmin) NodeHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Extract uuid
	uuid := r.PathValue("uuid")
	if uuid == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting uuid")
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastFutureTimes":         utils.PastFutureTimes,
		"bytesReceivedConversion": utils.BytesReceivedConversion,
		"jsonRawIndent":           jsonRawIndent,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "node.html").filepaths
	t, err := template.New("node.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting table template")
		return
	}
	// Get node by UUID
	node, err := h.Nodes.GetByUUID(uuid)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting node")
		return
	}
	// Get tags for the node
	nodeTags, err := h.Tags.GetTags(node)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags")
		return
	}
	// Get all tags decorated for this node
	tags, err := h.Tags.GetNodeTags(nodeTags)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags")
		return
	}
	// Get environment
	env, err := h.Envs.Get(node.Environment)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environment")
		return
	}
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, env.UUID) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Get all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// If dashboard enabled, retrieve packs and schedule
	dashboardEnabled := h.Settings.NodeDashboard(settings.NoEnvironmentID)
	var packs environments.PacksEntries
	var schedule environments.ScheduleConf
	if dashboardEnabled {
		packs, err = h.Envs.NodePacksEntries([]byte(env.Packs), node.Platform)
		if err != nil {
			h.Inc(metricAdminErr)
			log.Err(err).Msg("error getting packs")
			return
		}
		// Get the schedule for this environment
		schedule, err = h.Envs.NodeStructSchedule([]byte(env.Schedule), node.Platform)
		if err != nil {
			h.Inc(metricAdminErr)
			log.Err(err).Msg("error getting schedule")
			return
		}
	}
	leftMetadata := AsideLeftMetadata{
		EnvUUID:      env.UUID,
		ActiveNode:   nodes.IsActive(node, h.Settings.InactiveHours(settings.NoEnvironmentID)),
		InactiveNode: !nodes.IsActive(node, h.Settings.InactiveHours(settings.NoEnvironmentID)),
		NodeUUID:     node.UUID,
	}
	// Prepare template data
	templateData := NodeTemplateData{
		Title:         "Node View " + node.Hostname,
		EnvUUID:       env.UUID,
		Metadata:      h.TemplateMetadata(ctx, h.ServiceVersion),
		LeftMetadata:  leftMetadata,
		Node:          node,
		NodeTags:      nodeTags,
		TagsForNode:   tags,
		Environments:  h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:     platforms,
		Dashboard:     dashboardEnabled,
		Packs:         packs,
		Schedule:      schedule,
		ServiceConfig: *h.AdminConfig,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Node template served")
	}
	h.Inc(metricAdminOK)
}

// EnvsGETHandler for GET requests for /env
func (h *HandlersAdmin) EnvsGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "environments.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Prepare template data
	templateData := EnvironmentsTemplateData{
		Title:        "Manage environments",
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Environments template served")
	}
	h.Inc(metricAdminOK)
}

// SettingsGETHandler for GET requests for /settings
func (h *HandlersAdmin) SettingsGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Extract service
	serviceVar := r.PathValue("service")
	if serviceVar == "" {
		h.Inc(metricAdminErr)
		log.Info().Msg("error getting service")
		return
	}
	// Verify service
	if !checkTargetService(serviceVar) {
		h.Inc(metricAdminErr)
		log.Info().Msgf("error unknown service (%s)", serviceVar)
		return
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "settings.html").filepaths
	t, err := template.ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting settings template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get setting values
	_settings, err := h.Settings.RetrieveValues(serviceVar, false, settings.NoEnvironmentID)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting settings")
		return
	}
	// Get JSON values
	svcJSON, err := h.Settings.RetrieveAllJSON(serviceVar)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting JSON values")
	}
	// Prepare template data
	templateData := SettingsTemplateData{
		Title:           "Manage settings",
		Metadata:        h.TemplateMetadata(ctx, h.ServiceVersion),
		Service:         serviceVar,
		Environments:    h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:       platforms,
		CurrentSettings: _settings,
		ServiceConfig:   toJSONConfigurationService(svcJSON),
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Settings template served")
	}
	h.Inc(metricAdminOK)
}

// UsersGETHandler for GET requests for /users
func (h *HandlersAdmin) UsersGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastFutureTimes": utils.PastFutureTimes,
		"inFutureTime":    utils.InFutureTime,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "users.html").filepaths
	t, err := template.New("users.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting users template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get current users
	users, err := h.Users.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting users")
		return
	}
	// Prepare template data
	templateData := UsersTemplateData{
		Title:        "Manage users",
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		CurrentUsers: users,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Users template served")
	}
	h.Inc(metricAdminOK)
}

// TagsGETHandler for GET requests for /tags
func (h *HandlersAdmin) TagsGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.AdminLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastFutureTimes":   utils.PastFutureTimes,
		"inFutureTime":      utils.InFutureTime,
		"environmentFinder": environments.EnvironmentFinder,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "tags.html").filepaths
	t, err := template.New("tags.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get current tags
	tags, err := h.Tags.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting tags")
		return
	}
	// Prepare template data
	templateData := TagsTemplateData{
		Title:        "Manage tags",
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		Tags:         tags,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Tags template served")
	}
	h.Inc(metricAdminOK)
}

// EditProfileGETHandler for user profile edit
func (h *HandlersAdmin) EditProfileGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastFutureTimes": utils.PastFutureTimes,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "profile.html").filepaths
	t, err := template.New("profile.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting profile template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get current user
	user, err := h.Users.Get(ctx[sessions.CtxUser])
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting user")
		return
	}
	// Prepare template data
	templateData := ProfileTemplateData{
		Title:        "Edit " + user.Username + " profile",
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		CurrentUser:  user,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Profile template served")
	}
	h.Inc(metricAdminOK)
}

// DashboardGETHandler for dashboard page
func (h *HandlersAdmin) DashboardGETHandler(w http.ResponseWriter, r *http.Request) {
	h.Inc(metricAdminReq)
	utils.DebugHTTPDump(r, h.Settings.DebugHTTP(settings.ServiceAdmin, settings.NoEnvironmentID), false)
	// Get context data
	ctx := r.Context().Value(sessions.ContextKey(sessions.CtxSession)).(sessions.ContextValue)
	// Check permissions
	if !h.Users.CheckPermissions(ctx[sessions.CtxUser], users.UserLevel, users.NoEnvironment) {
		log.Info().Msgf("%s has insuficient permissions", ctx[sessions.CtxUser])
		h.Inc(metricAdminErr)
		return
	}
	// Custom functions to handle formatting
	funcMap := template.FuncMap{
		"pastFutureTimes": utils.PastFutureTimes,
	}
	// Prepare template
	tempateFiles := h.NewTemplateFiles(h.TemplatesFolder, "dashboard.html").filepaths
	t, err := template.New("dashboard.html").Funcs(funcMap).ParseFiles(tempateFiles...)
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting dashboard template")
		return
	}
	// Get stats for all environments
	envAll, err := h.Envs.All()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting environments")
		return
	}
	// Get stats for all platforms
	platforms, err := h.Nodes.GetAllPlatforms()
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting platforms")
		return
	}
	// Get current user
	user, err := h.Users.Get(ctx[sessions.CtxUser])
	if err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("error getting user")
		return
	}
	// Prepare template data
	templateData := DashboardTemplateData{
		Title:        "Dashboard for " + user.Username,
		Metadata:     h.TemplateMetadata(ctx, h.ServiceVersion),
		Environments: h.allowedEnvironments(ctx[sessions.CtxUser], envAll),
		Platforms:    platforms,
		CurrentUser:  user,
	}
	if err := t.Execute(w, templateData); err != nil {
		h.Inc(metricAdminErr)
		log.Err(err).Msg("template error")
		return
	}
	if h.Settings.DebugService(settings.ServiceAdmin) {
		log.Debug().Msg("DebugService: Dashboard template served")
	}
	h.Inc(metricAdminOK)
}
