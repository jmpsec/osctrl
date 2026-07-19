package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	// osquery version
	defOsqueryVersion = version.OsqueryVersion
	// path for enroll packages
	enrollPackagesPath = "packages"
)

// Valid values for actions in handlers
var validAction = map[string]bool{
	settings.ScriptEnroll: true,
	settings.ScriptRemove: true,
}

// Valid values for enroll packages
var validEnrollPackage = map[string]bool{
	settings.PackageDeb: true,
	settings.PackageRpm: true,
	settings.PackageMsi: true,
	settings.PackagePkg: true,
}

// Valid values for platforms in handlers
var validPlatform = map[string]bool{
	settings.PlatformDarwin:  true,
	settings.PlatformLinux:   true,
	settings.PlatformWindows: true,
}

// HandlersTLS to keep all handlers for TLS
type HandlersTLS struct {
	Envs            *environments.EnvManager
	EnvCache        *environments.EnvCache
	Nodes           *nodes.NodeManager
	Tags            *tags.TagManager
	Queries         *queries.Queries
	Carves          *carves.Carves
	Settings        *settings.Settings
	SettingsCache   *settings.RedisSettingsCache
	Logs            *logging.LoggerTLS
	WriteHandler    *batchWriter
	ActivityWriter  *activityWriter
	Posture         *posture.PostureManager
	OsqueryValues   *config.YAMLConfigurationOsquery
	ConfigEndpoints *config.YAMLConfigurationEndpoints
	DebugHTTP       *zerolog.Logger
	DebugHTTPConfig *config.YAMLConfigurationDebug
	AuditLog        *auditlog.AuditLogManager
}

// TLSResponse to be returned to requests
type TLSResponse struct {
	Message string `json:"message"`
}

// Option to pass to creator
type Option func(*HandlersTLS)

// WithEnvs to pass value as option
func WithEnvs(envs *environments.EnvManager) Option {
	return func(h *HandlersTLS) {
		h.Envs = envs
	}
}

// WithEnvCache sets a pre-built EnvCache (e.g., one with a Redis-backed
// invalidation check wired in). When provided, CreateHandlersTLS skips
// the default NewEnvCache call.
func WithEnvCache(ec *environments.EnvCache) Option {
	return func(h *HandlersTLS) {
		h.EnvCache = ec
	}
}

// WithSettings to pass value as option
func WithSettings(settings *settings.Settings) Option {
	return func(h *HandlersTLS) {
		h.Settings = settings
	}
}

// WithSettingsCache to pass Redis-backed TLS settings cache
func WithSettingsCache(settingsCache *settings.RedisSettingsCache) Option {
	return func(h *HandlersTLS) {
		h.SettingsCache = settingsCache
	}
}

// WithNodes to pass value as option
func WithNodes(nodes *nodes.NodeManager) Option {
	return func(h *HandlersTLS) {
		h.Nodes = nodes
	}
}

// WithTags to pass value as option
func WithTags(tags *tags.TagManager) Option {
	return func(h *HandlersTLS) {
		h.Tags = tags
	}
}

// WithQueries to pass value as option
func WithQueries(queries *queries.Queries) Option {
	return func(h *HandlersTLS) {
		h.Queries = queries
	}
}

// WithCarves to pass value as option
func WithCarves(carves *carves.Carves) Option {
	return func(h *HandlersTLS) {
		h.Carves = carves
	}
}

// WithLogs to pass value as option
func WithLogs(logs *logging.LoggerTLS) Option {
	return func(h *HandlersTLS) {
		h.Logs = logs
	}
}

// WithWriteHandler to pass value as option
func WithWriteHandler(writeHandler *batchWriter) Option {
	return func(h *HandlersTLS) {
		h.WriteHandler = writeHandler
	}
}

// WithActivityWriter to pass value as option
func WithActivityWriter(activityWriter *activityWriter) Option {
	return func(h *HandlersTLS) {
		h.ActivityWriter = activityWriter
	}
}

func WithPosture(pm *posture.PostureManager) Option {
	return func(h *HandlersTLS) {
		h.Posture = pm
	}
}

// WithOsqueryValues to pass osquery configuration values
func WithOsqueryValues(values *config.YAMLConfigurationOsquery) Option {
	return func(h *HandlersTLS) {
		h.OsqueryValues = values
	}
}

// WithConfigEndpoints to pass configuration endpoints values
func WithConfigEndpoints(endpoints *config.YAMLConfigurationEndpoints) Option {
	return func(h *HandlersTLS) {
		h.ConfigEndpoints = endpoints
	}
}

// WithDebugHTTP to pass debug HTTP configuration values
func WithDebugHTTP(cfg *config.YAMLConfigurationDebug) Option {
	return func(h *HandlersTLS) {
		h.DebugHTTPConfig = cfg
		h.DebugHTTP = nil
		if cfg.EnableHTTP {
			l, err := logging.CreateDebugHTTP(config.LocalLogger{
				FilePath:   cfg.HTTPFile,
				MaxSize:    25,
				MaxBackups: 5,
				MaxAge:     10,
				Compress:   true,
			})
			if err != nil {
				log.Err(err).Msg("error creating debug HTTP logger")
				l = nil
				h.DebugHTTPConfig.EnableHTTP = false
			}
			h.DebugHTTP = l
		}
	}
}

// WithAuditLog passes the audit-log manager so the TLS service can record
// failed enrollment attempts for SoC alerting.
func WithAuditLog(al *auditlog.AuditLogManager) Option {
	return func(h *HandlersTLS) {
		h.AuditLog = al
	}
}

// CreateHandlersTLS to initialize the TLS handlers struct
func CreateHandlersTLS(opts ...Option) *HandlersTLS {
	h := &HandlersTLS{}
	for _, opt := range opts {
		opt(h)
	}
	if h.Envs != nil && h.EnvCache == nil {
		h.EnvCache = environments.NewEnvCache(*h.Envs)
	}
	if h.AuditLog == nil {
		// Defensive — handlers call h.AuditLog.FailedEnroll(...). Disabled
		// manager is a no-op so we don't have to nil-check at every site.
		h.AuditLog = &auditlog.AuditLogManager{Enabled: false}
	}
	return h
}

// shouldDebugHTTP reports whether a request whose originating node UUID is
// `uuid` should be dumped to the debug HTTP log. It encodes the per-host
// filter introduced to make debug HTTP usable on busy servers:
//
//   - EnableHTTP off → never dump.
//   - TargetHostIdentifier empty → this returns false; the legacy "dump
//     everything" path is handled inline at the top of each handler
//     (gated on `TargetHostIdentifier == ""`), so non-empty-filter mode
//     stays byte-for-byte identical to the previous behavior.
//   - TargetHostIdentifier set → dump only when uuid matches, case-
//     insensitively. A zero uuid (failed node lookup / invalid key) never
//     matches, so anonymous or malformed traffic is excluded from the
//     filtered dump — which is the intent.
//
// Node UUIDs are stored uppercase and the osquery host_identifier may
// arrive in any case, so EqualFold is used on both sides.
func (h *HandlersTLS) shouldDebugHTTP(uuid string) bool {
	if h.DebugHTTPConfig == nil || !h.DebugHTTPConfig.EnableHTTP {
		return false
	}
	if h.DebugHTTPConfig.TargetHostIdentifier == "" {
		return false
	}
	return uuid != "" && strings.EqualFold(uuid, h.DebugHTTPConfig.TargetHostIdentifier)
}

// debugHTTPAll reports whether the legacy "dump every request" path
// should run at the top of a handler. It is true only when HTTP debug is
// enabled and no per-host filter is configured; in that mode behavior is
// identical to the previous implementation (full dump before the body is
// parsed, including malformed bodies). When a filter is set this returns
// false and the handler instead dumps only matching requests after the
// node has been identified, via shouldDebugHTTP + DebugHTTPDumpWithBody.
func (h *HandlersTLS) debugHTTPAll() bool {
	return h.DebugHTTPConfig != nil && h.DebugHTTPConfig.EnableHTTP && h.DebugHTTPConfig.TargetHostIdentifier == ""
}

func (h *HandlersTLS) acceleratedSeconds(ctx context.Context) int {
	if h.SettingsCache != nil {
		values, err := h.SettingsCache.GetMap(ctx)
		if err == nil {
			if value, ok := values[settings.AcceleratedSeconds]; ok {
				return int(value.Integer)
			}
		}
	}
	if h.Settings != nil {
		value, err := h.Settings.GetInteger(config.ServiceTLS, settings.AcceleratedSeconds, settings.NoEnvironmentID)
		if err == nil {
			return int(value)
		}
	}
	return 0
}

func (h *HandlersTLS) PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := NewResponseWriter(w)
		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()

		path := r.URL.Path
		method := r.Method
		statusCode := strconv.Itoa(rw.statusCode)
		requestDuration.WithLabelValues(method, path, statusCode).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
