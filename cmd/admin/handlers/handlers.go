package handlers

import (
	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// Default content
const errorContent = "❌"
const okContent = "✅"

// HandlersAdmin to keep all handlers for TLS
type HandlersAdmin struct {
	DB              *gorm.DB
	Users           *users.UserManager
	Tags            *tags.TagManager
	Envs            *environments.Environment
	Nodes           *nodes.NodeManager
	Queries         *queries.Queries
	Carves          *carves.Carves
	Settings        *settings.Settings
	RedisCache      *cache.RedisManager
	Sessions        *sessions.SessionManager
	ServiceVersion  string
	OsqueryVersion  string
	TemplatesFolder string
	StaticLocation  string
	CarvesFolder    string
	OsqueryTables   []types.OsqueryTable
	AdminConfig     *config.JSONConfigurationAdmin
	DBLogger        *logging.LoggerDB
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

func WithTags(tags *tags.TagManager) HandlersOption {
	return func(h *HandlersAdmin) {
		h.Tags = tags
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

func WithCarvesFolder(carves string) HandlersOption {
	return func(h *HandlersAdmin) {
		h.CarvesFolder = carves
	}
}

func WithCache(rds *cache.RedisManager) HandlersOption {
	return func(h *HandlersAdmin) {
		h.RedisCache = rds
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

func WithOsqueryVersion(version string) HandlersOption {
	return func(h *HandlersAdmin) {
		h.OsqueryVersion = version
	}
}

func WithTemplates(templates string) HandlersOption {
	return func(h *HandlersAdmin) {
		h.TemplatesFolder = templates
	}
}

func WithStaticLocation(offline bool) HandlersOption {
	return func(h *HandlersAdmin) {
		h.StaticLocation = "online"
		if offline {
			h.StaticLocation = "offline"
		}
	}
}

func WithOsqueryTables(tables []types.OsqueryTable) HandlersOption {
	return func(h *HandlersAdmin) {
		h.OsqueryTables = tables
	}
}

func WithAdminConfig(config *config.JSONConfigurationAdmin) HandlersOption {
	return func(h *HandlersAdmin) {
		h.AdminConfig = config
	}
}

func WithDBLogger(dbfile string, config *backend.JSONConfigurationDB) HandlersOption {
	return func(h *HandlersAdmin) {
		if dbfile == "" {
			if config == nil {
				h.DBLogger = nil
				return
			}
			logger, err := logging.CreateLoggerDBConfig(*config)
			if err != nil {
				log.Err(err).Msg("error creating DB logger (config)")
				logger = &logging.LoggerDB{
					Enabled:  false,
					Database: nil,
				}
			}
			h.DBLogger = logger
			return
		}
		logger, err := logging.CreateLoggerDBFile(dbfile)
		if err != nil {
			log.Err(err).Msg("error creating DB logger (file)")
			logger = &logging.LoggerDB{
				Enabled:  false,
				Database: nil,
			}
		}
		h.DBLogger = logger
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
