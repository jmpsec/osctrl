package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/ratelimit"
	"github.com/jmpsec/osctrl/pkg/utils"
)

// osctrldAuditPerHour caps failed-secret audit writes per environment, so
// a spray from many addresses cannot flood audit_logs.
const osctrldAuditPerHour = 60

// OsctrldLimits holds the per-process rate limiters of the osctrld routes.
// They key on utils.GetIP: the TCP peer, or the forwarded client when the
// peer is a configured trusted proxy (otherwise every client behind a proxy
// shares the proxy's budgets).
type OsctrldLimits struct {
	// Auth is charged only by wrong secrets, per address and environment.
	Auth *ratelimit.Limiter
	// Traffic is charged by every osctrld request, per address.
	Traffic *ratelimit.Limiter
	// Download is charged by every extension download, per address.
	Download *ratelimit.Limiter
	// authAudit lets one blocked rejection per Auth period reach the
	// audit log, per address and environment.
	authAudit *ratelimit.Limiter
	// auditCap bounds failed-secret audit writes per environment.
	auditCap *ratelimit.Limiter
}

// NewOsctrldLimits builds the osctrld limiters from the rate-limit config.
func NewOsctrldLimits(cfg config.YAMLConfigurationRateLimits) *OsctrldLimits {
	audit := cfg.OsctrldAuth
	audit.Burst = 1
	return &OsctrldLimits{
		Auth:      ratelimit.NewFromConfig(cfg.OsctrldAuth),
		Traffic:   ratelimit.NewFromConfig(cfg.Osctrld),
		Download:  ratelimit.NewFromConfig(cfg.OsctrldDownload),
		authAudit: ratelimit.NewFromConfig(audit),
		auditCap:  ratelimit.New(osctrldAuditPerHour, time.Hour, 2*time.Hour),
	}
}

// WithOsctrldLimits rate-limits the osctrld routes; nil leaves them unlimited.
func WithOsctrldLimits(l *OsctrldLimits) Option {
	return func(h *HandlersTLS) {
		h.OsctrldLimits = l
	}
}

// osctrldAuthKey keys the failed-secret budget by address and environment
// UUID, case-folded so spellings of one environment share a budget.
func osctrldAuthKey(ip, envUUID string) string {
	return ip + "|" + strings.ToLower(envUUID)
}

// OsctrldMiddleware wraps an osctrld route: the per-address traffic limit
// (and the download limit when download is set), then the failed-secret
// block, which turns a blocked address away before its body is read.
// Requests and latency are recorded by route pattern.
func (h *HandlersTLS) OsctrldMiddleware(download bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := NewResponseWriter(w)
		h.osctrldLimit(rw, r, download, next)
		requestDuration.WithLabelValues(r.Method, r.Pattern, strconv.Itoa(rw.statusCode)).Observe(time.Since(start).Seconds())
	})
}

func (h *HandlersTLS) osctrldLimit(w http.ResponseWriter, r *http.Request, download bool, next http.Handler) {
	l := h.OsctrldLimits
	if l == nil {
		next.ServeHTTP(w, r)
		return
	}
	reject := func(lim *ratelimit.Limiter, name string) {
		osctrldRateLimited.WithLabelValues(r.Pattern, name).Inc()
		lim.Reject(w)
	}
	ip := utils.GetIP(r)
	if !l.Traffic.Allow(ip) {
		reject(l.Traffic, "osctrld")
		return
	}
	if download && !l.Download.Allow(ip) {
		reject(l.Download, "osctrldDownload")
		return
	}
	// Cheap early rejection; osctrldSecret re-checks atomically.
	envVar := r.PathValue("env")
	if l.Auth.Exhausted(osctrldAuthKey(ip, envVar)) {
		h.osctrldBlocked(w, r, ip, envVar, nil)
		return
	}
	next.ServeHTTP(w, r)
}

// osctrldBlocked answers 429 for an address whose failed-secret budget for
// the environment is spent. The first rejection per Auth period is audited;
// env is resolved from envVar when nil.
func (h *HandlersTLS) osctrldBlocked(w http.ResponseWriter, r *http.Request, ip, envVar string, env *environments.TLSEnvironment) {
	l := h.OsctrldLimits
	if l.authAudit.Allow(osctrldAuthKey(ip, envVar)) {
		if env == nil {
			resolved := h.osctrldAuditEnv(r, envVar)
			env = &resolved
		}
		h.osctrldAudit(ip, *env, "blocked after too many failed secrets")
	}
	osctrldRateLimited.WithLabelValues(r.Pattern, "osctrldAuth").Inc()
	l.Auth.Reject(w)
}

// osctrldAudit writes a failed-secret audit entry unless the environment's
// audit cap is spent, in which case the drop is counted.
func (h *HandlersTLS) osctrldAudit(ip string, env environments.TLSEnvironment, reason string) {
	if l := h.OsctrldLimits; l != nil && !l.auditCap.Allow(strings.ToLower(env.UUID)) {
		osctrldAuthAuditDropped.WithLabelValues(env.Name).Inc()
		return
	}
	h.AuditLog.FailedOsctrld(ip, env.Name, reason, env.ID)
}

// osctrldAuditEnv resolves the environment in the path for an audit entry,
// falling back to the (UUID-validated) path value with no ID.
func (h *HandlersTLS) osctrldAuditEnv(r *http.Request, envVar string) environments.TLSEnvironment {
	if h.EnvCache != nil {
		if env, err := h.EnvCache.GetByUUID(r.Context(), strings.ToLower(envVar)); err == nil {
			return env
		}
	}
	if !utils.CheckUUID(envVar) {
		envVar = "<invalid>"
	}
	return environments.TLSEnvironment{UUID: envVar, Name: envVar}
}

// osctrldSecret checks the secret of an osctrld request. The budget check,
// the comparison and the charge for a wrong secret happen atomically, so
// requests that passed the middleware together cannot exceed the budget:
// once it is spent the request gets 429 without a comparison. A wrong
// secret is counted, audited (capped per environment) and answered 403.
func (h *HandlersTLS) osctrldSecret(w http.ResponseWriter, r *http.Request, secret string, env environments.TLSEnvironment) bool {
	valid := func() bool { return h.checkValidSecret(secret, env) }
	ip := utils.GetIP(r)
	if h.OsctrldLimits != nil {
		allowed, ok := h.OsctrldLimits.Auth.Attempt(osctrldAuthKey(ip, env.UUID), valid)
		if !allowed {
			h.osctrldBlocked(w, r, ip, env.UUID, &env)
			return false
		}
		if ok {
			return true
		}
	} else if valid() {
		return true
	}
	osctrldAuthFailures.WithLabelValues(env.Name).Inc()
	h.osctrldAudit(ip, env, "invalid secret")
	utils.HTTPResponse(w, "", http.StatusForbidden, []byte(""))
	return false
}
