package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog"
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
	Envs            *environments.Environment
	EnvsMap         *environments.MapEnvironments
	Nodes           *nodes.NodeManager
	Tags            *tags.TagManager
	Queries         *queries.Queries
	Carves          *carves.Carves
	Settings        *settings.Settings
	SettingsMap     *settings.MapSettings
	Logs            *logging.LoggerTLS
	WriteHandler    *batchWriter
	DebugHTTP       *zerolog.Logger
	DebugHTTPConfig *config.DebugHTTPConfiguration
}

// TLSResponse to be returned to requests
type TLSResponse struct {
	Message string `json:"message"`
}

// Option to pass to creator
type Option func(*HandlersTLS)

// WithEnvs to pass value as option
func WithEnvs(envs *environments.Environment) Option {
	return func(h *HandlersTLS) {
		h.Envs = envs
	}
}

// WithEnvsMap to pass value as option
func WithEnvsMap(envsmap *environments.MapEnvironments) Option {
	return func(h *HandlersTLS) {
		h.EnvsMap = envsmap
	}
}

// WithSettings to pass value as option
func WithSettings(settings *settings.Settings) Option {
	return func(h *HandlersTLS) {
		h.Settings = settings
	}
}

// WithSettingsMap to pass value as option
func WithSettingsMap(settingsmap *settings.MapSettings) Option {
	return func(h *HandlersTLS) {
		h.SettingsMap = settingsmap
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

func WithDebugHTTP(logger *zerolog.Logger, cfg *config.DebugHTTPConfiguration) Option {
	return func(h *HandlersTLS) {
		h.DebugHTTP = logger
		h.DebugHTTPConfig = cfg
	}
}

// CreateHandlersTLS to initialize the TLS handlers struct
func CreateHandlersTLS(opts ...Option) *HandlersTLS {
	h := &HandlersTLS{}
	for _, opt := range opts {
		opt(h)
	}
	// All these opt function need be refactored to reduce unnecessary complexity
	return h
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
