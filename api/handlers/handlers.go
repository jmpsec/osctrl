package handlers

import (
	"github.com/jmpsec/osctrl/cache"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"gorm.io/gorm"
)

const (
	metricAPIReq          = "api-req"
	metricAPIErr          = "api-err"
	metricAPIOK           = "api-ok"
	metricHealthReq       = "health-req"
	metricHealthOK        = "health-ok"
	metricAPICarvesReq    = "carves-req"
	metricAPICarvesErr    = "carves-err"
	metricAPICarvesOK     = "carves-ok"
	metricAPIEnvsReq      = "envs-req"
	metricAPIEnvsErr      = "envs-err"
	metricAPIEnvsOK       = "envs-ok"
	metricAPILoginReq     = "login-req"
	metricAPILoginErr     = "login-err"
	metricAPILoginOK      = "login-ok"
	metricAPINodesReq     = "nodes-req"
	metricAPINodesErr     = "nodes-err"
	metricAPINodesOK      = "nodes-ok"
	metricAPITagsReq      = "tags-req"
	metricAPITagsErr      = "tags-err"
	metricAPITagsOK       = "tags-ok"
	metricAPIUsersReq     = "users-req"
	metricAPIUsersErr     = "users-err"
	metricAPIUsersOK      = "users-ok"
	metricAPISettingsReq  = "settings-req"
	metricAPISettingsErr  = "settings-err"
	metricAPISettingsOK   = "settings-ok"
	metricAPIQueriesReq   = "queries-req"
	metricAPIQueriesErr   = "queries-err"
	metricAPIQueriesOK    = "queries-ok"
	metricAPIPlatformsReq = "platforms-req"
	metricAPIPlatformsErr = "platforms-err"
	metricAPIPlatformsOK  = "platforms-ok"
)

const errorContent = "❌"
const okContent = "✅"

type HandlersApi struct {
	DB             *gorm.DB
	Users          *users.UserManager
	Tags           *tags.TagManager
	Envs           *environments.Environment
	Nodes          *nodes.NodeManager
	Queries        *queries.Queries
	Carves         *carves.Carves
	Settings       *settings.Settings
	Metrics        *metrics.Metrics
	RedisCache     *cache.RedisManager
	ServiceVersion string
	ServiceName    string
	ApiConfig      *types.JSONConfigurationAPI
}

type HandlersOption func(*HandlersApi)

func WithDB(db *gorm.DB) HandlersOption {
	return func(h *HandlersApi) {
		h.DB = db
	}
}

func WithUsers(users *users.UserManager) HandlersOption {
	return func(h *HandlersApi) {
		h.Users = users
	}
}

func WithTags(tags *tags.TagManager) HandlersOption {
	return func(h *HandlersApi) {
		h.Tags = tags
	}
}

func WithEnvs(envs *environments.Environment) HandlersOption {
	return func(h *HandlersApi) {
		h.Envs = envs
	}
}

func WithNodes(nodes *nodes.NodeManager) HandlersOption {
	return func(h *HandlersApi) {
		h.Nodes = nodes
	}
}

func WithQueries(queries *queries.Queries) HandlersOption {
	return func(h *HandlersApi) {
		h.Queries = queries
	}
}

func WithCarves(carves *carves.Carves) HandlersOption {
	return func(h *HandlersApi) {
		h.Carves = carves
	}
}

func WithSettings(settings *settings.Settings) HandlersOption {
	return func(h *HandlersApi) {
		h.Settings = settings
	}
}

func WithMetrics(metrics *metrics.Metrics) HandlersOption {
	return func(h *HandlersApi) {
		h.Metrics = metrics
	}
}

func WithCache(rds *cache.RedisManager) HandlersOption {
	return func(h *HandlersApi) {
		h.RedisCache = rds
	}
}

func WithVersion(version string) HandlersOption {
	return func(h *HandlersApi) {
		h.ServiceVersion = version
	}
}

func WithName(name string) HandlersOption {
	return func(h *HandlersApi) {
		h.ServiceName = name
	}
}

// CreateHandlersApi to initialize the Admin handlers struct
func CreateHandlersApi(opts ...HandlersOption) *HandlersApi {
	h := &HandlersApi{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Inc - Helper to send metrics if it is enabled
func (h *HandlersApi) Inc(name string) {
	if h.Metrics != nil && h.Settings.ServiceMetrics(settings.ServiceAPI) {
		h.Metrics.Inc(name)
	}
}
