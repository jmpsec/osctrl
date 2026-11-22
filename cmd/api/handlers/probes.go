package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/utils"
)

// probeTimeout bounds every dependency check in the readiness probe. Probes
// are called frequently by orchestrators; a hung database must not hang the
// probe loop as well.
const probeTimeout = 2 * time.Second

// LivezHandler reports that the process is running and able to serve HTTP. It
// deliberately does not touch the database or Redis: liveness should restart a
// wedged process, not a process whose dependencies are temporarily down.
// @Summary Liveness probe
// @Description Returns 200 while the process is able to serve HTTP.
// @Tags checks
// @Produce json
// @Success 200 {string} string
// @Router /livez [get]
func (h *HandlersApi) LivezHandler(w http.ResponseWriter, r *http.Request) {
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

// ReadyzHandler reports whether this replica should receive traffic. Unlike
// /health (which returns 204 during stale-serve mode), readiness fails on a
// degraded database or an unreachable Redis so Kubernetes removes the replica
// from the service while it cannot serve authoritative reads.
// @Summary Readiness probe
// @Description Returns 200 when the database and Redis are reachable, 503 otherwise.
// @Tags checks
// @Produce json
// @Success 200 {string} string
// @Failure 503 {string} string "Dependency unavailable"
// @Router /readyz [get]
func (h *HandlersApi) ReadyzHandler(w http.ResponseWriter, r *http.Request) {
	if err := h.readinessCheck(r.Context()); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	utils.HTTPResponse(w, "", http.StatusOK, []byte(okContent))
}

func (h *HandlersApi) readinessCheck(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, probeTimeout)
	defer cancel()

	if h.DB == nil {
		return fmt.Errorf("database is not configured")
	}
	sqlDB, err := h.DB.DB()
	if err != nil {
		return fmt.Errorf("open database handle: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	if h.DBHealth != nil && h.DBHealth.IsDegraded() {
		return fmt.Errorf("database health monitor reports degraded")
	}

	// Redis is a required runtime dependency for both services. A replica
	// without it cannot serve shared caches, query dispatch or alert state.
	if h.Redis == nil {
		return fmt.Errorf("redis is not configured")
	}
	if err := h.Redis.CheckContext(ctx); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}
