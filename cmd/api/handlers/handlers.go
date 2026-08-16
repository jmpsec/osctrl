package handlers

import (
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/geoip"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/serviceconfig"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const errorContent = "❌"
const okContent = "✅"

type HandlersApi struct {
	DB *gorm.DB
	// LogReader is the read side of the status/result/query log store.
	// When the TLS logger writes to S3, this is the S3-backed reader so
	// the API can still surface logs to the frontend. When the logger
	// writes to the DB, this is the legacy GORM-backed reader. nil falls
	// back to h.DB via NewDBLogReader at call time so existing tests
	// that only wire WithDB keep working.
	LogReader     logging.LogReader
	Users         *users.UserManager
	Tags          *tags.TagManager
	Envs          *environments.EnvManager
	EnvCache      *environments.EnvCache
	Nodes         *nodes.NodeManager
	Queries       *queries.Queries
	Console       *console.Manager
	FileExplorer  *fileexplorer.Manager
	Carves        *carves.Carves
	Settings      *settings.Settings
	ServiceConfig *serviceconfig.ServiceConfigManager
	// ServiceConfigEnabled mirrors service.serviceConfigEnabled. When false
	// the service-config routes are never registered and the SPA hides the
	// section; the rows are still seeded and resolved at every boot.
	ServiceConfigEnabled bool
	ServiceCommands      *servicecommands.Manager
	Activity             activityReader
	GeoIP                *geoip.GeoIPResolver
	Posture              *posture.PostureManager
	PostureEnabled       bool
	// MFA owns the second-factor tables. Nil disables every MFA route.
	MFA *mfa.Manager
	// WebAuthn is nil when no RP ID or origin could be resolved, which
	// leaves TOTP and recovery codes working and hides passkey support.
	WebAuthn        *mfa.WebAuthn
	MFARequired     bool
	MFAIssuer       string
	ServiceVersion  string
	ServiceName     string
	AuditLog        *auditlog.AuditLogManager
	ApiConfig       *config.APIConfiguration
	DebugHTTP       *zerolog.Logger
	DebugHTTPConfig *config.YAMLConfigurationDebug
	OsqueryTables   []types.OsqueryTable
	OsqueryValues   config.YAMLConfigurationOsquery
	// JWTSecret is the HMAC key used by pkg/auth state-cookie
	// helpers. Populated via WithJWTSecret at handler init. Same
	// bytes the Users manager signs user JWTs with; the auth
	// state-cookie code uses audience claims to segregate uses.
	JWTSecret []byte
	// OIDCEnabled is the global toggle for federated login on
	// osctrl-api. When true, /api/v1/auth/methods advertises OIDC
	// and the OIDC login/callback routes initiate the federated
	// flow. When false, only password auth is offered. OIDC is
	// global because osctrl-api is a single-tenant API surface;
	// per-env identity provider config (if ever needed) would
	// belong on the operator layer, not here.
	OIDCEnabled bool
	// SAMLEnabled is the SAML analogue of OIDCEnabled. Same
	// semantics: global, single-tenant, advertised through
	// /api/v1/auth/methods. OIDC and SAML can both be on
	// simultaneously — the SPA renders one button per advertised
	// method.
	SAMLEnabled bool
	// DBHealth, when wired via WithDBHealth, lets HealthHandler
	// report backend degradation. nil means "no monitor" and the
	// health endpoint reports healthy as before.
	DBHealth backend.DegradedReader
	// RestartCh, when wired via WithRestartCh, is signalled by the
	// ServiceConfigApplyHandler to trigger a graceful shutdown so the
	// process manager restarts the service and picks up DB-edited
	// config. nil means the apply endpoint returns 503.
	RestartCh chan<- struct{}
	// ConfigPersist, when wired via WithConfigPersist, writes this
	// service's DB-edited config sections back to its own YAML file. It
	// lives in main because the YAML loader does. nil means the persist
	// endpoint returns 503 for osctrl-api.
	ConfigPersist func() error
}

type HandlersOption func(*HandlersApi)

func WithDB(db *gorm.DB) HandlersOption {
	return func(h *HandlersApi) {
		h.DB = db
	}
}

// WithLogReader wires a LogReader (DB- or S3-backed). When unset, the
// handlers fall back to NewDBLogReader(h.DB) so tests that only wire
// WithDB behave as before.
func WithLogReader(r logging.LogReader) HandlersOption {
	return func(h *HandlersApi) {
		h.LogReader = r
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

func WithEnvs(envs *environments.EnvManager) HandlersOption {
	return func(h *HandlersApi) {
		h.Envs = envs
	}
}

func WithEnvCache(envCache *environments.EnvCache) HandlersOption {
	return func(h *HandlersApi) {
		h.EnvCache = envCache
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

func WithConsole(consoleManager *console.Manager) HandlersOption {
	return func(h *HandlersApi) {
		h.Console = consoleManager
	}
}

func WithFileExplorer(fileExplorerManager *fileexplorer.Manager) HandlersOption {
	return func(h *HandlersApi) {
		h.FileExplorer = fileExplorerManager
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

func WithServiceConfig(mgr *serviceconfig.ServiceConfigManager) HandlersOption {
	return func(h *HandlersApi) {
		h.ServiceConfig = mgr
	}
}

func WithServiceCommands(mgr *servicecommands.Manager) HandlersOption {
	return func(h *HandlersApi) {
		h.ServiceCommands = mgr
	}
}

func WithActivityReader(ar activityReader) HandlersOption {
	return func(h *HandlersApi) {
		h.Activity = ar
	}
}

func WithGeoIP(g *geoip.GeoIPResolver) HandlersOption {
	return func(h *HandlersApi) {
		h.GeoIP = g
	}
}

func WithPosture(pm *posture.PostureManager) HandlersOption {
	return func(h *HandlersApi) {
		h.Posture = pm
	}
}

func WithPostureEnabled(enabled bool) HandlersOption {
	return func(h *HandlersApi) {
		h.PostureEnabled = enabled
	}
}

func WithServiceConfigEnabled(enabled bool) HandlersOption {
	return func(h *HandlersApi) {
		h.ServiceConfigEnabled = enabled
	}
}

// WithMFA wires the second-factor manager, the (optional) WebAuthn relying
// party and the deployment-wide requirement switch.
func WithMFA(manager *mfa.Manager, webAuthn *mfa.WebAuthn, required bool, issuer string) HandlersOption {
	return func(h *HandlersApi) {
		h.MFA = manager
		h.WebAuthn = webAuthn
		h.MFARequired = required
		h.MFAIssuer = issuer
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

func WithAuditLog(auditLog *auditlog.AuditLogManager) HandlersOption {
	return func(h *HandlersApi) {
		h.AuditLog = auditLog
	}
}

func WithOsqueryValues(values config.YAMLConfigurationOsquery) HandlersOption {
	return func(h *HandlersApi) {
		h.OsqueryValues = values
	}
}

func WithOsqueryTables(tables []types.OsqueryTable) HandlersOption {
	return func(h *HandlersApi) {
		h.OsqueryTables = tables
	}
}

func WithDebugHTTP(cfg *config.YAMLConfigurationDebug) HandlersOption {
	return func(h *HandlersApi) {
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

// WithJWTSecret attaches the HMAC key for auth state-cookie signing.
// MUST be the same secret pkg/users uses for user JWTs; the
// audience claim ("osctrl-auth-state" vs "osctrl-api") segregates
// the two purposes so sharing the underlying secret is safe.
func WithJWTSecret(secret []byte) HandlersOption {
	return func(h *HandlersApi) {
		h.JWTSecret = secret
	}
}

// WithOIDC toggles the global OIDC routes and the
// /api/v1/auth/methods response. Pass true at startup when the
// operator has configured an OIDC provider. When false,
// /api/v1/auth/methods returns password-only so the SPA renders
// the password form alone.
func WithOIDC(enabled bool) HandlersOption {
	return func(h *HandlersApi) {
		h.OIDCEnabled = enabled
	}
}

// WithSAML toggles the global SAML routes and the
// /api/v1/auth/methods response. SAML analogue of WithOIDC; the
// two can be enabled simultaneously.
func WithSAML(enabled bool) HandlersOption {
	return func(h *HandlersApi) {
		h.SAMLEnabled = enabled
	}
}

// WithDBHealth wires a DB health monitor so HealthHandler can
// report backend degradation (HTTP 204) instead of always reporting
// 200. Pass nil to keep the legacy "always healthy" behavior.
func WithDBHealth(hl backend.DegradedReader) HandlersOption {
	return func(h *HandlersApi) {
		h.DBHealth = hl
	}
}

func WithRestartCh(ch chan<- struct{}) HandlersOption {
	return func(h *HandlersApi) {
		h.RestartCh = ch
	}
}

func WithConfigPersist(fn func() error) HandlersOption {
	return func(h *HandlersApi) {
		h.ConfigPersist = fn
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

// logReader returns the wired LogReader, falling back to a DB-backed
// reader over h.DB so existing tests that only set WithDB keep working.
func (h *HandlersApi) logReader() logging.LogReader {
	if h.LogReader != nil {
		return h.LogReader
	}
	return logging.NewDBLogReader(h.DB)
}
