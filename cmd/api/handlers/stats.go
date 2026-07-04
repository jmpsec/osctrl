package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/activity"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// EnvStats is one row in the per-env breakdown returned by /api/v1/stats.
type EnvStats struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name"`
	Active        int64  `json:"active"`
	Inactive      int64  `json:"inactive"`
	Total         int64  `json:"total"`
	ActiveQueries int    `json:"active_queries"`
	ActiveCarves  int    `json:"active_carves"`
	// PlatformCounts buckets the env's nodes by OS family (linux / darwin /
	// windows / other). Drives the Nodes-table QuickFilters chip row. Counts
	// are total (active + inactive), since the filter chip lists all nodes
	// of that platform regardless of staleness — the Active/Inactive toggle
	// is independent.
	PlatformCounts nodes.PlatformCounts `json:"platform_counts"`
}

// StatsResponse is the canonical /api/v1/stats shape consumed by the dashboard.
type StatsResponse struct {
	// Cross-env totals (the user's allowed envs only).
	TotalNodes    int64 `json:"total_nodes"`
	ActiveNodes   int64 `json:"active_nodes"`
	InactiveNodes int64 `json:"inactive_nodes"`
	InactiveHours int64 `json:"inactive_hours"`
	// TotalActiveQueries counts standard query-type active queries (excludes carves).
	TotalActiveQueries int `json:"total_active_queries"`
	// TotalActiveCarves counts active carve-type queries.
	TotalActiveCarves int `json:"total_active_carves"`
	// Cross-env platform breakdown — sum of every accessible env's PlatformCounts.
	PlatformCounts nodes.PlatformCounts `json:"platform_counts"`

	// Per-env breakdown, in stable alphabetical order by name.
	Environments []EnvStats `json:"environments"`
}

// StatsHandler returns cross-env totals + per-env counts, filtered to the
// envs the calling user has UserLevel access to. Used by the SPA dashboard.
//
// No query params. The response is small (one entry per accessible env) and
// cacheable for 30s on the client (Cache-Control: private, max-age=30).
//
// NOTE on query/carve counting:
//   - GetActive(envID) returns ALL active rows regardless of type (union).
//   - To avoid double-counting we call GetQueries("active", envID) for
//     standard queries and GetCarves("active", envID) for carves separately.
//   - Unit test for this handler is deferred: the underlying pkg/queries
//     functions are exercised by existing tests in pkg/queries; a full
//     integration test would require DB fixture setup that is out of scope
//     for Track 2.
//
// @Summary Get dashboard stats
// @Description Returns cross-environment dashboard statistics.
// @Tags stats
// @Produce json
// @Success 200 {object} StatsResponse
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats [get]
func (h *HandlersApi) StatsHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	allEnvs, err := h.Envs.All()
	if err != nil {
		apiErrorResponse(w, "failed to load environments", http.StatusInternalServerError, err)
		return
	}

	hours := h.Settings.InactiveHours(settings.NoEnvironmentID)
	out := StatsResponse{
		InactiveHours: hours,
		Environments:  make([]EnvStats, 0, len(allEnvs)),
	}

	for _, e := range allEnvs {
		// Filter to envs the user can actually see.
		if !h.Users.CheckPermissions(user, users.UserLevel, e.UUID) {
			continue
		}

		ns, err := h.Nodes.GetStatsByEnv(e.Name, hours)
		if err != nil {
			log.Warn().Err(err).Str("env", e.Name).Msg("stats: failed to get node stats, skipping env")
			continue
		}

		// Per-env platform counts (linux / darwin / windows / other) for the
		// SPA's filter chips. We don't fail the whole env on a count error;
		// if the GROUP BY fails the env still gets a row, just with zeros in
		// PlatformCounts. The SPA renders the chips as "0" rather than missing.
		platCounts, err := h.Nodes.GetPlatformCountsByEnv(e.Name)
		if err != nil {
			log.Warn().Err(err).Str("env", e.Name).Msg("stats: failed to get platform counts, defaulting to zeros")
		}

		// Use type-specific methods to avoid double-counting:
		//   GetQueries returns StandardQueryType active items only.
		//   GetCarves  returns CarveQueryType active items only.
		activeQ, err := h.Queries.GetQueries(queries.TargetActive, e.ID)
		if err != nil {
			log.Warn().Err(err).Str("env", e.Name).Msg("stats: failed to count active queries, skipping env")
			continue
		}
		activeC, err := h.Queries.GetCarves(queries.TargetActive, e.ID)
		if err != nil {
			log.Warn().Err(err).Str("env", e.Name).Msg("stats: failed to count active carves, skipping env")
			continue
		}

		row := EnvStats{
			UUID:           e.UUID,
			Name:           e.Name,
			Active:         ns.Active,
			Inactive:       ns.Inactive,
			Total:          ns.Total,
			ActiveQueries:  len(activeQ),
			ActiveCarves:   len(activeC),
			PlatformCounts: platCounts,
		}
		out.Environments = append(out.Environments, row)
		out.ActiveNodes += ns.Active
		out.InactiveNodes += ns.Inactive
		out.TotalNodes += ns.Total
		out.TotalActiveQueries += len(activeQ)
		out.TotalActiveCarves += len(activeC)
		// Aggregate cross-env platform totals.
		out.PlatformCounts.Linux += platCounts.Linux
		out.PlatformCounts.Darwin += platCounts.Darwin
		out.PlatformCounts.Windows += platCounts.Windows
		out.PlatformCounts.Other += platCounts.Other
	}

	// Stable alphabetical order by env name.
	sort.Slice(out.Environments, func(i, j int) bool {
		return out.Environments[i].Name < out.Environments[j].Name
	})

	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// ActivityBucket is one cell of the 24-hour activity heatmap. BucketStart is
// the start of the 15-minute window (UTC, RFC3339); the four counters are
// the audit-log entry counts that fell into that window for each category.
//
// Categories (audit log_type → category):
//   - config  ← Setting (8) + Environment (7)
//   - query   ← Query (4)
//   - carve   ← Carve (5)
//   - enroll  ← Node (3) — covers enroll, archive, deletion
type ActivityBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Config      int       `json:"config"`
	Query       int       `json:"query"`
	Carve       int       `json:"carve"`
	Enroll      int       `json:"enroll"`
}

// activityIntervalPresets maps the SPA's interval picker values to (hours,
// bucketSeconds). Bucket sizes are chosen so the cell count stays in the
// 36..96 range across the full picker — small enough to fit one row at
// 1280px, large enough that the heatmap still reads as a sparse density map.
//
// Adding a new preset: pick a bucketSeconds that divides hours*3600 evenly
// to avoid an under-filled trailing cell.
type activityPreset struct {
	bucketSeconds int
}

// activityAllowedBucketSeconds gates the ?bucket_seconds override on the
// per-node activity endpoint. The SPA renders a fixed-column heatmap, so it
// requests window/N bucket sizes that vary per interval (e.g. 450s, 5400s,
// 12600s). Rather than maintain an ever-growing allowlist, accept any size that
// is at least 5 minutes — fine enough to be useful, coarse enough that even a
// 7-day window stays bounded (~2000 buckets max). The handler still requires
// the size to divide the window evenly, which rejects arbitrary primes.
func activityAllowedBucketSeconds(v int) bool {
	return v >= 300
}

var activityIntervalPresets = map[string]activityPreset{
	"3h":  {bucketSeconds: 5 * 60},   // 36 cells
	"6h":  {bucketSeconds: 5 * 60},   // 72 cells
	"12h": {bucketSeconds: 10 * 60},  // 72 cells
	"1d":  {bucketSeconds: 15 * 60},  // 96 cells
	"2d":  {bucketSeconds: 30 * 60},  // 96 cells
	"3d":  {bucketSeconds: 45 * 60},  // 96 cells
	"7d":  {bucketSeconds: 2 * 3600}, // 84 cells
}

var activityIntervalHours = map[string]int{
	"3h": 3, "6h": 6, "12h": 12, "1d": 24, "2d": 48, "3d": 72, "7d": 168,
}

// EnvActivityHandler — GET /api/v1/stats/activity/{env}?interval=KEY
//
// Returns audit-log activity for one env over the requested interval,
// bucketed at a fixed size per interval (see activityIntervalPresets).
// `interval` accepts 3h / 6h / 12h / 1d / 2d / 3d / 7d (default 1d, falls
// back to 1d on any unknown value rather than 400ing — the SPA picker is
// the only allowed source).
//
// Buckets are emitted contiguously — empty windows return zero rows for
// that bucket — so the SPA can render the grid without densifying
// client-side.
// @Summary Get environment activity
// @Description Returns activity buckets for an environment.
// @Tags stats
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param hours query int false "Number of hours to include"
// @Success 200 {object} ActivityBucket
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/activity/{env} [get]
func (h *HandlersApi) EnvActivityHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if !h.Users.CheckPermissions(user, users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", user))
		return
	}

	intervalKey := r.URL.Query().Get("interval")
	preset, ok := activityIntervalPresets[intervalKey]
	if !ok {
		intervalKey = "1d"
		preset = activityIntervalPresets["1d"]
	}
	hours := activityIntervalHours[intervalKey]
	bucketSeconds := preset.bucketSeconds
	totalSeconds := hours * 3600
	nBuckets := totalSeconds / bucketSeconds

	// Align the strip to the most-recent 15-min boundary so the rightmost
	// column always represents "now" rather than a partial bucket. Avoids
	// the visual confusion of an under-filled trailing cell.
	now := time.Now().UTC()
	endBucket := time.Unix((now.Unix()/int64(bucketSeconds))*int64(bucketSeconds), 0).UTC()
	startBucket := endBucket.Add(-time.Duration(nBuckets-1) * time.Duration(bucketSeconds) * time.Second)

	rows, err := h.AuditLog.GetEnvActivityBucketed(env.ID, startBucket, bucketSeconds)
	if err != nil {
		apiErrorResponse(w, "failed to load activity", http.StatusInternalServerError, err)
		return
	}

	// Pre-allocate the contiguous bucket array so empty windows still ship a
	// row. Indexing is by `(bucket_start - startUnix) / bucketSeconds`,
	// floor-clamped to [0, nBuckets-1].
	startUnix := startBucket.Unix()
	out := make([]ActivityBucket, nBuckets)
	for i := range out {
		out[i].BucketStart = startBucket.Add(time.Duration(i) * time.Duration(bucketSeconds) * time.Second)
	}
	for _, row := range rows {
		idx := int((row.BucketStart - startUnix) / int64(bucketSeconds))
		if idx < 0 || idx >= nBuckets {
			continue
		}
		switch row.LogType {
		case auditlog.LogTypeSetting, auditlog.LogTypeEnvironment:
			out[idx].Config += int(row.Cnt)
		case auditlog.LogTypeQuery:
			out[idx].Query += int(row.Cnt)
		case auditlog.LogTypeCarve:
			out[idx].Carve += int(row.Cnt)
		case auditlog.LogTypeNode:
			out[idx].Enroll += int(row.Cnt)
		}
	}

	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// NodeActivityBucket is one cell of the per-node 24h activity heatmap.
// Categories pivot from the env-scoped variant — node-scoped activity is
// about what THIS device has been doing, not what operators have done to
// the env. So:
//   - status  ← osquery_status_data row count (status logs received from this node)
//   - result  ← osquery_result_data row count (query results returned by this node)
//   - query   ← node_queries row count (distributed queries scheduled against this node)
//   - carve   ← carved_files row count (carves this node has produced)
//
// All four are joinable by node uuid (or numeric node id for node_queries).
type NodeActivityBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Status      int       `json:"status"`
	Result      int       `json:"result"`
	Query       int       `json:"query"`
	Carve       int       `json:"carve"`
}

// NodeActivityHandler — GET /api/v1/stats/activity/node/{env}/{uuid}?interval=KEY
//
// Per-node version of EnvActivityHandler. Same bucketing rules (see
// activityIntervalPresets). The four categories partition different DB
// tables (see NodeActivityBucket) keyed by the node's UUID — except
// node_queries which keys by numeric NodeID, looked up once from the
// resolved node.
// @Summary Get node activity
// @Description Returns activity buckets for a node.
// @Tags stats
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param hours query int false "Number of hours to include"
// @Success 200 {object} NodeActivityBucket
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/activity/node/{env}/{uuid} [get]
func (h *HandlersApi) NodeActivityHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	envVar := r.PathValue("env")
	uuidVar := r.PathValue("uuid")
	if envVar == "" || uuidVar == "" {
		apiErrorResponse(w, "env and uuid required", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if !h.Users.CheckPermissions(user, users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", user))
		return
	}
	// Resolve the node — gives us the numeric NodeID for the node_queries
	// join and lets us reject probes for arbitrary UUIDs across tenants.
	node, err := h.Nodes.GetByUUID(uuidVar)
	if err != nil {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if !strings.EqualFold(node.Environment, env.Name) {
		apiErrorResponse(w, "node not in environment", http.StatusForbidden, nil)
		return
	}

	intervalKey := r.URL.Query().Get("interval")
	preset, ok := activityIntervalPresets[intervalKey]
	if !ok {
		intervalKey = "1d"
		preset = activityIntervalPresets["1d"]
	}
	hours := activityIntervalHours[intervalKey]
	bucketSeconds := preset.bucketSeconds
	// Optional ?bucket_seconds override lets the SPA align the per-node heatmap
	// to an hourly grid so it can merge in the Redis-backed config series (which
	// is hourly). Only accepted when it is one of the preset sizes and divides
	// the window evenly; anything else falls back to the interval default.
	if bs := r.URL.Query().Get("bucket_seconds"); bs != "" {
		if v, err := strconv.Atoi(bs); err == nil && activityAllowedBucketSeconds(v) && hours*3600%v == 0 {
			bucketSeconds = v
		}
	}
	totalSeconds := hours * 3600
	nBuckets := totalSeconds / bucketSeconds

	now := time.Now().UTC()
	endBucket := time.Unix((now.Unix()/int64(bucketSeconds))*int64(bucketSeconds), 0).UTC()
	startBucket := endBucket.Add(-time.Duration(nBuckets-1) * time.Duration(bucketSeconds) * time.Second)

	out := h.computeNodeActivityForNode(env.Name, node.UUID, node.ID, startBucket, bucketSeconds, nBuckets)
	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// computeNodeActivityForNode runs the 4-table bucketed-count pipeline for
// one node and returns the dense bucket array. Shared by both
// NodeActivityHandler and NodeActivityBatchHandler so the bucketing rules
// stay in one place.
//
// Each category issues a single SQL GROUP BY rather than plucking every
// CreatedAt — at 50k+ nodes a chatty status_data table would otherwise
// stream tens of thousands of timestamps per Nodes page row.
// Fail-soft per category: a single-table error still renders the others.
func (h *HandlersApi) computeNodeActivityForNode(
	envName string,
	nodeUUID string,
	nodeID uint,
	startBucket time.Time,
	bucketSeconds int,
	nBuckets int,
) []NodeActivityBucket {
	startUnix := startBucket.Unix()

	statusRows, err := logging.GetNodeStatusBucketed(h.DB, envName, nodeUUID, startBucket, bucketSeconds)
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg("node-activity: status bucketed failed")
	}
	resultRows, err := logging.GetNodeResultBucketed(h.DB, envName, nodeUUID, startBucket, bucketSeconds)
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg("node-activity: result bucketed failed")
	}
	queryRows, err := h.Queries.GetNodeQueryBucketed(nodeID, startBucket, bucketSeconds)
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg("node-activity: node-query bucketed failed")
	}
	carveRows, err := h.Carves.GetNodeCarveBucketed(nodeUUID, startBucket, bucketSeconds)
	if err != nil {
		log.Warn().Err(err).Str("node", nodeUUID).Msg("node-activity: carve bucketed failed")
	}

	statusDense := dbutil.DensifyBuckets(statusRows, startUnix, bucketSeconds, nBuckets)
	resultDense := dbutil.DensifyBuckets(resultRows, startUnix, bucketSeconds, nBuckets)
	queryDense := dbutil.DensifyBuckets(queryRows, startUnix, bucketSeconds, nBuckets)
	carveDense := dbutil.DensifyBuckets(carveRows, startUnix, bucketSeconds, nBuckets)

	out := make([]NodeActivityBucket, nBuckets)
	for i := range out {
		out[i].BucketStart = startBucket.Add(time.Duration(i) * time.Duration(bucketSeconds) * time.Second)
		out[i].Status = int(statusDense[i])
		out[i].Result = int(resultDense[i])
		out[i].Query = int(queryDense[i])
		out[i].Carve = int(carveDense[i])
	}
	return out
}

// NodeActivityBatchHandler — GET /api/v1/stats/activity/node-batch/{env}?uuids=A,B,C&interval=KEY
//
// Returns activity buckets for up to 100 nodes in one call. The response is
// a map keyed by node UUID so the SPA can render a sparkline per row in the
// Nodes table without firing N parallel requests.
//
// Cap is 100 to bound the per-request DB load — each node still requires 4
// timestamp queries. The SPA's pagination is already <=500 page size; for
// pages above 100 nodes the SPA fans out 2-3 batch requests instead.
//
// Unknown / unauthorized UUIDs are silently omitted from the response
// (they're treated as "no data"), not 404'd — that lets a single bad UUID
// in the list not break the whole page render.
// @Summary Get node activity batch
// @Description Returns activity buckets for multiple nodes in an environment.
// @Tags stats
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuids query string false "Comma-separated node UUIDs"
// @Param hours query int false "Number of hours to include"
// @Success 200 {object} map[string][]NodeActivityBucket
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/activity/node-batch/{env} [get]
func (h *HandlersApi) NodeActivityBatchHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "env required", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if !h.Users.CheckPermissions(user, users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", user))
		return
	}

	uuidsParam := strings.TrimSpace(r.URL.Query().Get("uuids"))
	if uuidsParam == "" {
		// Empty request → empty response. Avoids the page from breaking when
		// the SPA's `nodes` query returns 0 rows (zero-length CSV).
		utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, map[string][]NodeActivityBucket{})
		return
	}
	rawUUIDs := strings.Split(uuidsParam, ",")
	const maxBatch = 100
	if len(rawUUIDs) > maxBatch {
		rawUUIDs = rawUUIDs[:maxBatch]
	}
	// Dedupe + normalize (upper-case, like the DB stores them).
	seen := make(map[string]struct{}, len(rawUUIDs))
	uuids := rawUUIDs[:0]
	for _, u := range rawUUIDs {
		u = strings.ToUpper(strings.TrimSpace(u))
		if u == "" {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		uuids = append(uuids, u)
	}

	intervalKey := r.URL.Query().Get("interval")
	preset, ok := activityIntervalPresets[intervalKey]
	if !ok {
		intervalKey = "1d"
		preset = activityIntervalPresets["1d"]
	}
	hours := activityIntervalHours[intervalKey]
	bucketSeconds := preset.bucketSeconds
	totalSeconds := hours * 3600
	nBuckets := totalSeconds / bucketSeconds

	now := time.Now().UTC()
	endBucket := time.Unix((now.Unix()/int64(bucketSeconds))*int64(bucketSeconds), 0).UTC()
	startBucket := endBucket.Add(-time.Duration(nBuckets-1) * time.Duration(bucketSeconds) * time.Second)

	out := make(map[string][]NodeActivityBucket, len(uuids))
	for _, u := range uuids {
		// Per-uuid resolution. A miss is logged-but-skipped rather than
		// failed-the-whole-batch — see handler comment for rationale.
		node, err := h.Nodes.GetByUUID(u)
		if err != nil {
			log.Debug().Err(err).Str("node", u).Msg("node-activity-batch: uuid not found, skipping")
			continue
		}
		if !strings.EqualFold(node.Environment, env.Name) {
			log.Debug().Str("node", u).Msg("node-activity-batch: uuid not in env, skipping")
			continue
		}
		out[node.UUID] = h.computeNodeActivityForNode(env.Name, node.UUID, node.ID, startBucket, bucketSeconds, nBuckets)
	}

	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// OsqueryVersionsHandler — GET /api/v1/stats/osquery-versions.
//
// Returns fleet-wide osquery agent version breakdown for the dashboard's
// "fleet hygiene" panel. Operators use this to spot stale agents that need
// upgrading. Cross-env (no env filter); the dashboard already surfaces the
// per-env breakdown in its env tiles.
//
// Counts include both active and inactive nodes — a node sitting at an old
// osquery version is still "stale" even if it's offline today, because once
// it comes back online it'll come back stale.
// @Summary Get osquery version stats
// @Description Returns fleet-wide osquery version counts.
// @Tags stats
// @Produce json
// @Success 200 {object} nodes.OsqueryVersionCount
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 409 {object} types.ApiErrorResponse "Conflict"
// @Failure 429 {object} types.ApiErrorResponse "Too many requests"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/osquery-versions [get]
func (h *HandlersApi) OsqueryVersionsHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	rows, err := h.Nodes.GetOsqueryVersionCounts()
	if err != nil {
		apiErrorResponse(w, "failed to load osquery versions", http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=60")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, rows)
}

// activityReader decouples the tile handlers from the concrete Redis store so
// they can be unit-tested with a stub. *activity.RedisStore satisfies this.
type activityReader interface {
	ReadSeries(ctx context.Context, envUUID string, nodeUUIDs []string, end time.Time, days int) (map[string]activity.NodeTileSeries, error)
	ReadEnvSeries(ctx context.Context, envUUID string, end time.Time, days int) (activity.EnvSeries, error)
}

// activityTileDays parses and clamps the ?days query parameter for the
// tile endpoints. The Redis rollups keep DefaultRetentionDays of history, so
// anything above that would just return empty trailing buckets. Defaults to
// 1 day (last 24h) when absent or invalid, matching the SPA's default view.
func activityTileDays(raw string) int {
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 1
	}
	if n > activity.DefaultRetentionDays {
		return activity.DefaultRetentionDays
	}
	return n
}

// NodeActivityTilesHandler — GET /api/v1/stats/activity/node-tiles/{env}/{uuid}?days=N
//
// Returns the Redis-backed per-node activity series: hourly counters for
// enroll / config / status / result / query_read / query_write / total over
// the last N days (default 1, capped at retention). This is the finer-grained
// counterpart to the DB-backed NodeActivityHandler: it carries the config and
// read/write split the DB buckets collapse into a single "query" category, so
// the SPA can show per-endpoint last-seen activity.
//
// Returns 503 when the activity store is not configured (Redis unavailable).
// @Summary Get per-node activity tiles
// @Description Returns Redis-backed hourly activity series for a node.
// @Tags stats
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param uuid path string true "Node UUID"
// @Param days query int false "Days of history (1-7, default 1)"
// @Success 200 {object} activity.NodeTileSeries
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/activity/node-tiles/{env}/{uuid} [get]
func (h *HandlersApi) NodeActivityTilesHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	envVar := r.PathValue("env")
	uuidVar := r.PathValue("uuid")
	if envVar == "" || uuidVar == "" {
		apiErrorResponse(w, "env and uuid required", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if !h.Users.CheckPermissions(user, users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", user))
		return
	}
	node, err := h.Nodes.GetByUUID(uuidVar)
	if err != nil {
		apiErrorResponse(w, "node not found", http.StatusNotFound, err)
		return
	}
	if !strings.EqualFold(node.Environment, env.Name) {
		apiErrorResponse(w, "node not in environment", http.StatusForbidden, nil)
		return
	}
	if h.Activity == nil {
		apiErrorResponse(w, "activity store not configured", http.StatusServiceUnavailable, nil)
		return
	}

	days := activityTileDays(r.URL.Query().Get("days"))
	series, err := h.Activity.ReadSeries(r.Context(), env.UUID, []string{node.UUID}, time.Now(), days)
	if err != nil {
		apiErrorResponse(w, "failed to load activity tiles", http.StatusInternalServerError, err)
		return
	}

	out, ok := series[node.UUID]
	if !ok {
		// ReadSeries always returns an entry for every requested uuid, but
		// guard anyway so a future implementation change can't 500 the SPA.
		out = activity.NodeTileSeries{Start: time.Now(), BucketSeconds: activity.BucketSeconds}
	}
	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}

// EnvActivityTilesHandler — GET /api/v1/stats/activity/env-tiles/{env}?days=N
//
// Redis-backed environment-level activity series (same shape as the node
// variant, aggregated across all nodes in the env).
//
// Returns 503 when the activity store is not configured (Redis unavailable).
// @Summary Get environment activity tiles
// @Description Returns Redis-backed hourly activity series for an environment.
// @Tags stats
// @Produce json
// @Param env path string true "Environment name or UUID"
// @Param days query int false "Days of history (1-7, default 1)"
// @Success 200 {object} activity.EnvSeries
// @Failure 400 {object} types.ApiErrorResponse "Bad request"
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 404 {object} types.ApiErrorResponse "Not found"
// @Failure 500 {object} types.ApiErrorResponse "Internal server error"
// @Failure 503 {object} types.ApiErrorResponse "Service unavailable"
// @Security ApiKeyAuth
// @Router /api/v1/stats/activity/env-tiles/{env} [get]
func (h *HandlersApi) EnvActivityTilesHandler(w http.ResponseWriter, r *http.Request) {
	ctxVal := r.Context().Value(ContextKey(contextAPI))
	if ctxVal == nil {
		apiErrorResponse(w, "missing auth context", http.StatusUnauthorized, nil)
		return
	}
	ctx := ctxVal.(ContextValue)
	user := ctx[ctxUser]

	envVar := r.PathValue("env")
	if envVar == "" {
		apiErrorResponse(w, "error with environment", http.StatusBadRequest, nil)
		return
	}
	env, err := h.Envs.Get(envVar)
	if err != nil {
		apiErrorResponse(w, "error getting environment", http.StatusNotFound, err)
		return
	}
	if !h.Users.CheckPermissions(user, users.UserLevel, env.UUID) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use API by user %s", user))
		return
	}
	if h.Activity == nil {
		apiErrorResponse(w, "activity store not configured", http.StatusServiceUnavailable, nil)
		return
	}

	days := activityTileDays(r.URL.Query().Get("days"))
	out, err := h.Activity.ReadEnvSeries(r.Context(), env.UUID, time.Now(), days)
	if err != nil {
		apiErrorResponse(w, "failed to load activity tiles", http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Cache-Control", "private, max-age=30")
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, out)
}
