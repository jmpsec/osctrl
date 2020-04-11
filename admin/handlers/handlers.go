package handlers

import (
	"github.com/jinzhu/gorm"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
)

const (
	metricJSONReq   = "admin-json-req"
	metricJSONErr   = "admin-json-err"
	metricJSONOK    = "admin-json-ok"
	metricHealthReq = "health-req"
	metricHealthOK  = "health-ok"
	metricAdminReq  = "admin-req"
	metricAdminErr  = "admin-err"
	metricAdminOK   = "admin-ok"
	metricTokenReq  = "admin-token-req"
	metricTokenErr  = "admin-token-err"
	metricTokenOK   = "admin-token-ok"
)

// Empty default osquery configuration
const emptyConfiguration string = "data/osquery-empty.json"

const errorContent = "❌"
const okContent = "✅"

// HandlersAdmin to keep all handlers for TLS
type HandlersAdmin struct {
	DB             *gorm.DB
	Users          *users.UserManager
	Envs           *environments.Environment
	Nodes          *nodes.NodeManager
	Queries        *queries.Queries
	Carves         *carves.Carves
	Settings       *settings.Settings
	Metrics        *metrics.Metrics
	LoggerDB       *logging.LoggerDB
	Sessions       *sessions.SessionManager
	ServiceVersion string
	OsqueryTables  []types.OsqueryTable
	AdminConfig    *types.JSONConfigurationService
}

type HandlersOption func(*HandlersAdmin)

func WithDB(db *gorm.DB) HandlersOption {
	return func(h *HandlersAdmin) {
		h.DB = db
	}
}

func WithEnvs(envs *environments.Environment) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Envs = envs
	}
}

func WithUsers(users *users.UserManager) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Users = users
	}
}

func WithSettings(settings *settings.Settings) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Settings = settings
	}
}

func WithNodes(nodes *nodes.NodeManager) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Nodes = nodes
	}
}

func WithQueries(queries *queries.Queries) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Queries = queries
	}
}

func WithCarves(carves *carves.Carves) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Carves = carves
	}
}

func WithMetrics(metrics *metrics.Metrics) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Metrics = metrics
	}
}

func WithLoggerDB(logger *logging.LoggerDB) HandlersOption {
	return func(h *HandlersAdmin) {
		h.LoggerDB = logger
	}
}

func WithSessions(sessions *sessions.SessionManager) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Sessions = sessions
	}
}

func WithVersion(version string) HandlersOption {
	return func(h *HandlersAdmin) {
		h.ServiceVersion = version
	}
}

func WithOsqueryTables(tables []types.OsqueryTable) HandlersOption {
	return func(h *HandlersAdmin) {
		h.OsqueryTables = tables
	}
}

func WithAdminConfig(config *types.JSONConfigurationService) HandlersOption {
	return func(h *HandlersAdmin) {
		h.AdminConfig = config
	}
}

// CreateHandlersAdmin to initialize the Admin handlers struct
func CreateHandlersAdmin(opts ...HandlersOption) *HandlersAdmin {
	h := &HandlersAdmin{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Inc - Helper to send metrics if it is enabled
func (h *HandlersAdmin) Inc(name string) {
	if h.Metrics != nil && h.Settings.ServiceMetrics(settings.ServiceAdmin) {
		h.Metrics.Inc(name)
	}
}
