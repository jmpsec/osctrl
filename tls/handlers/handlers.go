package handlers

import (
	"net/http"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/version"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricEnrollReq   = "enroll-req"
	metricEnrollErr   = "enroll-err"
	metricEnrollOK    = "enroll-ok"
	metricLogReq      = "log-req"
	metricLogErr      = "log-err"
	metricLogOK       = "log-ok"
	metricConfigReq   = "config-req"
	metricConfigErr   = "config-err"
	metricConfigOK    = "config-ok"
	metricReadReq     = "read-req"
	metricReadErr     = "read-err"
	metricReadOK      = "read-ok"
	metricWriteReq    = "write-req"
	metricWriteErr    = "write-err"
	metricWriteOK     = "write-ok"
	metricInitReq     = "init-req"
	metricInitErr     = "init-err"
	metricInitOK      = "init-ok"
	metricBlockReq    = "block-req"
	metricBlockErr    = "block-err"
	metricBlockOK     = "block-ok"
	metricHealthReq   = "health-req"
	metricHealthOK    = "health-ok"
	metricOnelinerReq = "oneliner-req"
	metricOnelinerErr = "oneliner-err"
	metricOnelinerOk  = "oneliner-ok"
	metricPackageReq  = "package-req"
	metricPackageErr  = "package-err"
	metricPackageOk   = "package-ok"
	metricFlagsReq    = "flags-req"
	metricFlagsErr    = "flags-err"
	metricFlagsOk     = "flags-ok"
	metricCertReq     = "cert-req"
	metricCertErr     = "cert-err"
	metricCertOk      = "cert-ok"
	metricScriptReq   = "script-req"
	metricScriptErr   = "script-err"
	metricScriptOk    = "script-ok"
	metricVerifyReq   = "verify-req"
	metricVerifyErr   = "verify-err"
	metricVerifyOk    = "verify-ok"
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
	Envs        *environments.Environment
	EnvsMap     *environments.MapEnvironments
	Nodes       *nodes.NodeManager
	Tags        *tags.TagManager
	Queries     *queries.Queries
	Carves      *carves.Carves
	Settings    *settings.Settings
	SettingsMap *settings.MapSettings
	Metrics     *metrics.Metrics
	Ingested    *metrics.IngestedManager
	Logs        *logging.LoggerTLS
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

// WithMetrics to pass value as option
func WithMetrics(metrics *metrics.Metrics) Option {
	return func(h *HandlersTLS) {
		h.Metrics = metrics
	}
}

// WithIngested to pass value as option
func WithIngested(ingested *metrics.IngestedManager) Option {
	return func(h *HandlersTLS) {
		h.Ingested = ingested
	}
}

// WithLogs to pass value as option
func WithLogs(logs *logging.LoggerTLS) Option {
	return func(h *HandlersTLS) {
		h.Logs = logs
	}
}

// CreateHandlersTLS to initialize the TLS handlers struct
func CreateHandlersTLS(opts ...Option) *HandlersTLS {
	h := &HandlersTLS{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Inc - Helper to send metrics if it is enabled
func (h *HandlersTLS) Inc(name string) {
	if h.Metrics != nil && h.Settings.ServiceMetrics(settings.ServiceTLS) {
		h.Metrics.Inc(name)
	}
}

func (h *HandlersTLS) prometheusMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := prometheus.NewTimer(requestDuration.WithLabelValues(r.Method, r.URL.Path, "200"))
			defer timer.ObserveDuration()
			next.ServeHTTP(w, r)

		})
	}
}
