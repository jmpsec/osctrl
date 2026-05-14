package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// carveFileView projects a CarvedFile row into the SPA-canonical envelope.
// time.Time stays as time.Time so JSON-encoded output is RFC3339.
func carveFileView(c carves.CarvedFile) types.CarveFileView {
	return types.CarveFileView{
		CarveID:         c.CarveID,
		SessionID:       c.SessionID,
		UUID:            c.UUID,
		Path:            c.Path,
		Status:          c.Status,
		CarveSize:       c.CarveSize,
		BlockSize:       c.BlockSize,
		TotalBlocks:     c.TotalBlocks,
		CompletedBlocks: c.CompletedBlocks,
		Archived:        c.Archived,
		CreatedAt:       c.CreatedAt,
		CompletedAt:     c.CompletedAt,
	}
}

// CarveShowHandler - GET /api/v1/carves/{env}/{name}
//
// Returns the carve query metadata plus the array of per-node CarvedFile rows
// produced by the carve. Returns 404 when the carve query name does not exist
// in the environment.
func (h *HandlersApi) CarveShowHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	name := r.PathValue("name")
	if name == "" {
		apiErrorResponse(w, "error getting name", http.StatusBadRequest, nil)
		return
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	// Look up the carve query (DistributedQuery row with type=carve).
	q, err := h.Queries.Get(name, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "carve not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting carve", http.StatusInternalServerError, err)
		return
	}
	if q.Type != queries.CarveQueryType {
		apiErrorResponse(w, "carve not found", http.StatusNotFound, nil)
		return
	}

	// Look up the carved files (one per node that completed the carve).
	files, err := h.Carves.GetByQuery(name, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting carve files", http.StatusInternalServerError, err)
		return
	}
	views := make([]types.CarveFileView, 0, len(files))
	for _, f := range files {
		views = append(views, carveFileView(f))
	}

	resp := types.CarveDetailResponse{Query: q, Files: views}
	log.Debug().Msgf("Returned carve %s (%d files)", name, len(views))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// CarveQueriesHandler - GET /api/v1/carves/{env}/queries/{target}
//
// Returns carve queries by target. Retained from the legacy contract; the
// canonical list endpoint is now CarveListHandler at /api/v1/carves/{env}.
func (h *HandlersApi) CarveQueriesHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	targetVar := r.PathValue("target")
	if targetVar == "" {
		apiErrorResponse(w, "error with target", http.StatusBadRequest, nil)
		return
	}
	if !QueryTargets[targetVar] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, nil)
		return
	}
	carvesList, err := h.Queries.GetCarves(targetVar, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting carve queries", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Returned %d carves", len(carvesList))
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, carvesList)
}

// CarveListHandler - GET /api/v1/carves/{env}
//
// Paginated, sorted, searchable list of carve queries (DistributedQuery rows
// with type=carve). Query params: page, page_size, q, sort, dir, target.
// Empty result → HTTP 200 with items: [].
func (h *HandlersApi) CarveListHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	search := q.Get("q")
	sortCol := q.Get("sort")
	desc := strings.ToLower(q.Get("dir")) != "asc"
	target := q.Get("target")
	if target == "" {
		target = queries.TargetAll
	}
	if !QueryTargets[target] {
		apiErrorResponse(w, "invalid target", http.StatusBadRequest, nil)
		return
	}

	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	if page <= 0 {
		page = 1
	}

	result, err := h.Queries.GetByEnvTargetPaged(env.ID, target, queries.CarveQueryType, search, page, pageSize, sortCol, desc)
	if err != nil {
		apiErrorResponse(w, "error getting carves", http.StatusInternalServerError, err)
		return
	}
	items := result.Items
	if items == nil {
		items = []queries.DistributedQuery{}
	}
	var totalPages int
	if result.TotalItems > 0 {
		totalPages = int((result.TotalItems + int64(pageSize) - 1) / int64(pageSize))
	}
	resp := types.CarvesPagedResponse{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		TotalItems: result.TotalItems,
		TotalPages: totalPages,
	}
	log.Debug().Msgf("Returned %d carves (page %d of %d)", len(items), page, totalPages)
	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, resp)
}

// CarvesRunHandler - POST /api/v1/carves/{env}
func (h *HandlersApi) CarvesRunHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var c types.ApiDistributedQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		apiErrorResponse(w, "error parsing POST body", http.StatusBadRequest, err)
		return
	}
	if c.Path == "" {
		apiErrorResponse(w, "path can not be empty", http.StatusBadRequest, nil)
		return
	}
	// Validate the path before it's spliced into the osquery SQL via
	// carves.GenCarveQuery. Without this gate a CarveLevel operator
	// could inject arbitrary osquery (e.g. `'; SELECT 1; --`) into the
	// query that gets distributed to every targeted node — pivoting
	// "carve a file" into "run any SELECT".
	if !carves.ValidCarvePath(c.Path) {
		apiErrorResponse(w, "invalid carve path", http.StatusBadRequest, fmt.Errorf("rejected path %q", c.Path))
		return
	}
	// Make sure the user has permissions to run queries in the environments
	for _, e := range c.Environments {
		if !h.Users.CheckPermissions(ctx[ctxUser], users.QueryLevel, e) {
			apiErrorResponse(w, fmt.Sprintf("%s has insufficient permissions to run queries in environment %s", ctx[ctxUser], e), http.StatusForbidden, nil)
			return
		}
	}
	expTime := queries.QueryExpiration(c.ExpHours)
	if c.ExpHours == 0 {
		expTime = time.Time{}
	}
	newQuery := queries.DistributedQuery{
		Query:         carves.GenCarveQuery(c.Path, false),
		Name:          carves.GenCarveName(),
		Creator:       ctx[ctxUser],
		Active:        true,
		Expiration:    expTime,
		Type:          queries.CarveQueryType,
		Path:          c.Path,
		EnvironmentID: env.ID,
	}
	if err := h.Queries.Create(&newQuery); err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	data := handlers.ProcessingQuery{
		Envs:          c.Environments,
		Platforms:     c.Platforms,
		UUIDs:         c.UUIDs,
		Hosts:         c.Hosts,
		Tags:          c.Tags,
		EnvID:         env.ID,
		InactiveHours: h.Settings.InactiveHours(settings.NoEnvironmentID),
	}
	manager := handlers.Managers{
		Nodes: h.Nodes,
		Envs:  h.Envs,
		Tags:  h.Tags,
	}
	targetNodesID, err := handlers.CreateQueryCarve(data, manager, newQuery)
	if err != nil {
		apiErrorResponse(w, "error creating query", http.StatusInternalServerError, err)
		return
	}
	if len(targetNodesID) != 0 {
		if err := h.Queries.CreateNodeQueries(targetNodesID, newQuery.ID); err != nil {
			log.Err(err).Msgf("error creating node queries for carve %s", newQuery.Name)
			apiErrorResponse(w, "error creating node queries", http.StatusInternalServerError, err)
			return
		}
	}
	if err := h.Queries.SetExpected(newQuery.Name, len(targetNodesID), env.ID); err != nil {
		apiErrorResponse(w, "error setting expected", http.StatusInternalServerError, err)
		return
	}
	log.Debug().Msgf("Created carve %s", newQuery.Name)
	h.AuditLog.NewCarve(ctx[ctxUser], newQuery.Path, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusCreated, types.ApiQueriesResponse{Name: newQuery.Name})
}

// CarvesActionHandler - POST /api/v1/carves/{env}/{action}/{name}
func (h *HandlersApi) CarvesActionHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}
	var msgReturn string
	nameVar := r.PathValue("name")
	if nameVar == "" {
		apiErrorResponse(w, "name can not be empty", http.StatusBadRequest, nil)
		return
	}
	if !h.Queries.Exists(nameVar, env.ID) {
		apiErrorResponse(w, "carve not found", http.StatusNotFound, nil)
		return
	}
	actionVar := r.PathValue("action")
	if actionVar == "" {
		apiErrorResponse(w, "error getting action", http.StatusBadRequest, nil)
		return
	}
	switch actionVar {
	case settings.CarveDelete:
		if err := h.Queries.Delete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error deleting carve", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("carve %s deleted successfully", nameVar)
	case settings.CarveExpire:
		if err := h.Queries.Expire(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error expiring carve", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("carve %s expired successfully", nameVar)
	case settings.CarveComplete:
		if err := h.Queries.Complete(nameVar, env.ID); err != nil {
			apiErrorResponse(w, "error completing carve", http.StatusInternalServerError, err)
			return
		}
		msgReturn = fmt.Sprintf("carve %s completed successfully", nameVar)
	default:
		apiErrorResponse(w, "invalid action", http.StatusBadRequest, nil)
		return
	}
	log.Debug().Msgf("%s", msgReturn)
	h.AuditLog.CarveAction(ctx[ctxUser], actionVar+" carve "+nameVar, strings.Split(r.RemoteAddr, ":")[0], env.ID)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, types.ApiGenericResponse{Message: msgReturn})
}

// CarveArchiveHandler - GET /api/v1/carves/{env}/archive/{name}
//
// (The literal `archive` lives in segment 2 — not as a `/{name}/archive` suffix —
// because Go's ServeMux refuses to register patterns that ambiguously overlap with
// `/{env}/queries/{target}` registered on the same prefix.)
//
// Streams (or redirects to) the reassembled carve archive blob.
//
// Resolution rules:
//   - The carve query identified by {name} must exist and be type=carve.
//   - If exactly one CarvedFile exists for the query, it is served.
//   - If multiple exist, an explicit ?session=<session-id> must select one.
//     A missing/ambiguous session selector returns 409 Conflict.
//   - If the underlying file is not yet archived, it is archived on demand
//     (local or DB carver: written to a temp dir, then served; S3: a presigned
//     download URL is returned via 302 redirect).
//
// Content-Disposition is set to attachment with the carve archive filename.
func (h *HandlersApi) CarveArchiveHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, h.DebugHTTPConfig.ShowBody)
	}
	envVar := r.PathValue("env")
	name := r.PathValue("name")
	if envVar == "" || name == "" {
		apiErrorResponse(w, "missing env or name", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusInternalServerError, nil)
		return
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.CarveLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", ctx[ctxUser]))
		return
	}

	// Confirm the carve query exists and is a carve.
	q, err := h.Queries.Get(name, env.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			apiErrorResponse(w, "carve not found", http.StatusNotFound, err)
			return
		}
		apiErrorResponse(w, "error getting carve", http.StatusInternalServerError, err)
		return
	}
	if q.Type != queries.CarveQueryType {
		apiErrorResponse(w, "carve not found", http.StatusNotFound, nil)
		return
	}

	files, err := h.Carves.GetByQuery(name, env.ID)
	if err != nil {
		apiErrorResponse(w, "error getting carve files", http.StatusInternalServerError, err)
		return
	}
	if len(files) == 0 {
		apiErrorResponse(w, "no carved files yet", http.StatusNotFound, nil)
		return
	}

	requestedSession := strings.TrimSpace(r.URL.Query().Get("session"))
	var selected *carves.CarvedFile
	switch {
	case requestedSession != "":
		for i := range files {
			if files[i].SessionID == requestedSession {
				selected = &files[i]
				break
			}
		}
		if selected == nil {
			apiErrorResponse(w, "session not found for carve", http.StatusNotFound, nil)
			return
		}
	case len(files) == 1:
		selected = &files[0]
	default:
		// Ambiguous — the caller must pick a session.
		sessions := make([]string, 0, len(files))
		for _, f := range files {
			sessions = append(sessions, f.SessionID)
		}
		apiErrorResponse(w,
			fmt.Sprintf("carve has %d files; pass ?session=<id> to select one (sessions: %s)",
				len(files), strings.Join(sessions, ", ")),
			http.StatusConflict, nil)
		return
	}

	// Materialize the archive if not already done. The path persistence
	// strategy differs by carver:
	//
	//   - S3:        Archive() multipart-uploads the file to a persistent S3
	//                key; we mark the row archived with that key and serve
	//                a presigned download URL.
	//   - Local/DB:  Archive() reconstructs the file in a workspace dir. The
	//                API process owns no canonical "carves folder" — the
	//                legacy admin owns one — so we stage in a per-request
	//                tmpdir, stream, and do NOT persist the path. (Persisting
	//                would point future requests at a tmpdir we've already
	//                removed.) The trade-off is re-archiving on each request
	//                for local/DB carvers, which is correctness over cache.
	carve := *selected

	if h.Carves.Carver == config.CarverS3 {
		if !carve.Archived {
			// Pass empty destPath — Archive() ignores it for the S3 path.
			result, aerr := h.Carves.Archive(carve.SessionID, "")
			if aerr != nil {
				apiErrorResponse(w, "error archiving carve", http.StatusInternalServerError, aerr)
				return
			}
			if result == nil {
				apiErrorResponse(w, "empty carve archive", http.StatusInternalServerError, nil)
				return
			}
			if aerr := h.Carves.ArchiveCarve(carve.SessionID, result.File); aerr != nil {
				log.Err(aerr).Msgf("error marking carve %s archived", carve.SessionID)
			}
			carve.Archived = true
			carve.ArchivePath = result.File
		}
		link, lerr := h.Carves.S3.GetDownloadLink(carve)
		if lerr != nil {
			apiErrorResponse(w, "error generating download link", http.StatusInternalServerError, lerr)
			return
		}
		h.AuditLog.CarveAction(ctx[ctxUser], "download "+name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
		http.Redirect(w, r, link, http.StatusFound)
		return
	}

	// Local / DB carver: stage the archive in a per-request tmpdir and stream
	// it back. RemoveAll runs after f.Close (defers are LIFO), so the file is
	// readable for the duration of the response.
	//
	// os.MkdirTemp creates the directory mode 0700, but the file written
	// inside by Carves.Archive may end up world-readable depending on
	// the platform umask. We chmod it to 0600 explicitly so on a
	// multi-tenant container host another tenant on the same node can't
	// read the carved bytes during the brief window before RemoveAll.
	//
	archivePath := carve.ArchivePath
	if !carve.Archived {
		tmpDir, terr := os.MkdirTemp("", "osctrl-carve-archive-")
		if terr != nil {
			apiErrorResponse(w, "error preparing archive workspace", http.StatusInternalServerError, terr)
			return
		}
		defer os.RemoveAll(tmpDir)
		result, aerr := h.Carves.Archive(carve.SessionID, tmpDir)
		if aerr != nil {
			apiErrorResponse(w, "error archiving carve", http.StatusInternalServerError, aerr)
			return
		}
		if result == nil {
			apiErrorResponse(w, "empty carve archive", http.StatusInternalServerError, nil)
			return
		}
		archivePath = result.File
		if err := os.Chmod(archivePath, 0600); err != nil {
			log.Err(err).Msgf("failed to chmod 0600 on carve archive %s — proceeding but file may be wider-readable", archivePath)
		}
	}

	f, ferr := os.Open(archivePath)
	if ferr != nil {
		apiErrorResponse(w, "error opening archive", http.StatusInternalServerError, ferr)
		return
	}
	defer f.Close()
	stat, serr := f.Stat()
	if serr != nil {
		apiErrorResponse(w, "error stat archive", http.StatusInternalServerError, serr)
		return
	}
	filename := carves.GenerateArchiveName(carve)
	// If the on-disk file picked up the zst suffix during archive, preserve it.
	if strings.HasSuffix(archivePath, carves.ZstFileExtension) &&
		!strings.HasSuffix(filename, carves.ZstFileExtension) {
		filename += carves.ZstFileExtension
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size(), 10))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		log.Err(err).Msgf("error streaming carve archive %s", archivePath)
		return
	}
	h.AuditLog.CarveAction(ctx[ctxUser], "download "+name, strings.Split(r.RemoteAddr, ":")[0], env.ID)
}
