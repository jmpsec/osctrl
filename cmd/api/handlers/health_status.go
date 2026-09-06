package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/health"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// healthStatusResponse is the payload the SPA renders. One response carries
// every component and its details, so the page's drill-downs are expansions
// rather than extra round trips.
type healthStatusResponse struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Components  []health.Component `json:"components"`
	Upgrade     health.UpgradeInfo `json:"upgrade"`
}

// HealthStatusHandler — GET /api/v1/health/status
//
// @Summary Deployment health
// @Description Component health, per-service runtime detail and upgrade status. Admin only.
// @Tags health
// @Produce json
// @Success 200 {object} healthStatusResponse
// @Failure 401 {object} types.ApiErrorResponse "Unauthorized"
// @Failure 403 {object} types.ApiErrorResponse "Forbidden"
// @Failure 503 {object} types.ApiErrorResponse "Health reporting disabled"
// @Security ApiKeyAuth
// @Router /api/v1/health/status [get]
func (h *HandlersApi) HealthStatusHandler(w http.ResponseWriter, r *http.Request) {
	if h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP {
		utils.DebugHTTPDump(h.DebugHTTP, r, false)
	}
	ctx := r.Context().Value(ContextKey(contextAPI)).(ContextValue)
	if !h.Users.CheckPermissions(ctx[ctxUser], users.AdminLevel, users.NoEnvironment) {
		apiErrorResponse(w, "no access", http.StatusForbidden, fmt.Errorf("attempt to use health API by user %s", ctx[ctxUser]))
		return
	}
	if h.Health == nil {
		apiErrorResponse(w, "health reporting not enabled", http.StatusServiceUnavailable, nil)
		return
	}

	now := time.Now()
	components := []health.Component{
		h.databaseComponent(r),
		h.redisComponent(),
		h.apiComponent(),
	}

	row, err := h.Health.Get(config.ServiceTLS)
	components = append(components,
		health.ServiceComponent(row, err, now, h.ServiceVersion),
		health.WorkersComponent(row, err, now),
	)

	upgrade := health.UpgradeInfo{Current: h.ServiceVersion}
	if h.HealthVersions != nil {
		upgrade = h.HealthVersions.Info(row.Version)
	}

	h.AuditLog.Visit(ctx[ctxUser], r.URL.Path, strings.Split(r.RemoteAddr, ":")[0], auditlog.NoEnvironment)
	utils.HTTPResponse(w, utils.JSONApplicationUTF8, http.StatusOK, healthStatusResponse{
		GeneratedAt: now,
		Components:  components,
		Upgrade:     upgrade,
	})
}

// databaseComponent pings the database, on top of the existing background
// health monitor's verdict.
func (h *HandlersApi) databaseComponent(r *http.Request) health.Component {
	var degraded bool
	if h.DBHealth != nil {
		degraded = h.DBHealth.IsDegraded()
	}
	start := time.Now()
	var pingErr error
	sqlDB, err := h.DB.DB()
	if err != nil {
		pingErr = err
	} else {
		pingErr = sqlDB.PingContext(r.Context())
	}
	return health.DatabaseComponent(degraded, pingErr, time.Since(start))
}

// redisComponent reuses the existing cache manager check.
func (h *HandlersApi) redisComponent() health.Component {
	start := time.Now()
	var err error
	if h.Redis == nil {
		err = fmt.Errorf("redis is not configured")
	} else {
		err = h.Redis.Check()
	}
	return health.RedisComponent(err, time.Since(start))
}

// apiComponent reports this process. It is operational by definition — it
// answered the request — so the value here is the runtime detail.
func (h *HandlersApi) apiComponent() health.Component {
	stats := health.Snapshot(h.StartedAt)
	return health.Component{
		ID:      "api",
		Name:    "osctrl-api",
		Status:  health.StatusOperational,
		Summary: fmt.Sprintf("up %s, %d goroutines", time.Since(h.StartedAt).Round(time.Minute), stats.Goroutines),
		Details: map[string]any{
			"version":        h.ServiceVersion,
			"uptime_seconds": stats.UptimeSeconds,
			"goroutines":     stats.Goroutines,
			"runtime":        stats,
		},
	}
}
