package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/activity"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/authproviders"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/geoip"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/logsinks"
	"github.com/jmpsec/osctrl/pkg/mfa"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osquery"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/ratelimit"
	"github.com/jmpsec/osctrl/pkg/servicecommands"
	"github.com/jmpsec/osctrl/pkg/serviceconfig"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"

	"github.com/spf13/viper"
)

const (
	// Project name
	projectName = "osctrl"
	// Service name
	serviceName = projectName + "-" + config.ServiceAPI
	// Service description
	serviceDescription = "API service for osctrl"
	// Application description
	appDescription = serviceDescription + ", a fast and efficient osquery management"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
)

// Build-time metadata (overridden via -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...")
var (
	buildVersion = version.OsctrlVersion
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// Paths
const (
	// HTTP health path
	healthPath = "/health"
	// HTTP errors path
	errorPath     = "/error"
	forbiddenPath = "/forbidden"
	// API checks path
	checksNoAuthPath = "/checks-no-auth"
	checksAuthPath   = "/checks-auth"
	// API prefix path
	apiPrefixPath = "/api"
	// API version path
	apiVersionPath = "/v1"
	// API login path
	apiLoginPath = "/login"
	apiMFAPath   = "/mfa"
	// API nodes path
	apiNodesPath = "/nodes"
	// API queries path
	apiQueriesPath = "/queries"
	// API saved queries path
	apiSavedQueriesPath = "/saved-queries"
	// API users path
	apiUsersPath = "/users"
	// API all queries path
	apiAllQueriesPath = "/all-queries"
	// API carves path
	apiCarvesPath = "/carves"
	// API platforms path
	apiPlatformsPath = "/platforms"
	// API environments path
	apiEnvironmentsPath = "/environments"
	// API tags path
	apiTagsPath = "/tags"
	// API settings path
	apiSettingsPath = "/settings"
	// API service config path
	apiServiceConfigPath = "/service-config"
	// API log sinks path
	apiLogSinksPath = "/log-sinks"
	apiAuthProvidersPath = "/auth-providers"
	// API features path
	apiFeaturesPath = "/features"
	// API file explorer path
	apiFileExplorerPath = "/file-explorer"
	// API audit logs path
	apiAuditLogsPath = "/audit-logs"
	// API logs path
	apiLogsPath = "/logs"
	// API stats path
	apiStatsPath = "/stats"
	// API osquery path
	apiOsqueryPath = "/osquery"
	// API auth methods / federated login path. Global (no
	// {env}) because OIDC on osctrl-api is a single, deployment-
	// wide identity surface; env scoping happens at the user-
	// permissions layer, not the auth layer.
	apiAuthPath = "/auth"
)

// Global variables
var (
	err                  error
	db                   *backend.DBManager
	redis                *cache.RedisManager
	apiUsers             *users.UserManager
	tagsmgr              *tags.TagManager
	settingsmgr          *settings.Settings
	envs                 *environments.EnvManager
	nodesmgr             *nodes.NodeManager
	queriesmgr           *queries.Queries
	consolemgr           *console.Manager
	fileexplorermgr      *fileexplorer.Manager
	filecarves           *carves.Carves
	handlersApi          *handlers.HandlersApi
	app                  *cli.Command
	flags                []cli.Flag
	serviceConfiguration config.APIConfiguration
	// FIXME this struct is temporary until we refactor to write settings to the DB
	flagParams    *config.ServiceParameters
	auditLog      *auditlog.AuditLogManager
	osqueryTables []types.OsqueryTable
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	config.AuthNone: true,
	config.AuthJWT:  true,
}

// Function to load the configuration from a single YAML file
func loadYAMLConfiguration(file string) (config.APIConfiguration, error) {
	var cfg config.APIConfiguration
	// saml.forceAuthn defaults to true — same as the --saml-force-authn
	// flag. Without this the YAML path would silently land on false for
	// any config file that omits the key, which most operators read as
	// "logout didn't work" (the IdP silently re-auths from its own SSO
	// cookie). A zero-value bool can't distinguish "absent" from
	// "explicitly false", so the default has to live here.
	viper.SetDefault("saml.forceAuthn", true)
	// Load file and read config
	viper.SetConfigFile(file)
	viper.SetConfigType(config.YAMLConfigType)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Unmarshal into struct
	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Service.Auth] {
		return cfg, fmt.Errorf("invalid auth method: '%s'", cfg.Service.Auth)
	}
	if cfg.RateLimits != nil {
		if err := config.ValidateRateLimits(*cfg.RateLimits, "login", "preAuth", "serviceConfigApply"); err != nil {
			return cfg, err
		}
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize default flagParams
	flagParams = &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{},
		DB:      &config.YAMLConfigurationDB{},
		Redis:   &config.YAMLConfigurationRedis{},
		JWT:     &config.YAMLConfigurationJWT{},
		OIDC:    &config.YAMLConfigurationOIDC{},
		SAML:    &config.YAMLConfigurationSAML{},
		TLS:     &config.YAMLConfigurationTLS{},
		Osquery: &config.YAMLConfigurationOsquery{},
		Logger: &config.YAMLConfigurationLogger{
			DB:       &config.YAMLConfigurationDB{},
			S3:       &config.S3Logger{},
			Graylog:  &config.GraylogLogger{},
			Elastic:  &config.ElasticLogger{},
			Splunk:   &config.SplunkLogger{},
			Logstash: &config.LogstashLogger{},
			Kinesis:  &config.KinesisLogger{},
			Kafka:    &config.KafkaLogger{},
			Local:    &config.LocalLogger{},
		},
		Carver: &config.YAMLConfigurationCarver{
			S3:    &config.S3Carver{},
			Local: &config.LocalCarver{},
		},
		Debug:      &config.YAMLConfigurationDebug{},
		RateLimits: config.DefaultRateLimitsPtr(),
	}
	// Initialize CLI flags using the config package
	flags = config.InitAPIFlags(flagParams)
}

// Retrieve latest release information and compare
func checkLatestRelease() {
	log.Info().Msg("Checking for the latest release...")
	latest, err := version.RetrieveVersionData(version.VersionDataURL)
	if err != nil {
		log.Err(err).Msg("Error retrieving latest release information")
		return
	}
	if version.CheckSuggestedRelease(latest.SuggestedRelease) {
		log.Info().Msgf("%s (%s) is up to date with the suggested release (%s), latest %s", serviceName, buildVersion, latest.SuggestedRelease, latest.LatestRelease)
	} else {
		log.Info().Msgf("Please upgrade %s to at least %s. Latest version available: %s (current: %s)", serviceName, latest.SuggestedRelease, latest.LatestRelease, buildVersion)
		log.Info().Msgf("Release notes: %s", latest.MoreInformation)
	}
}

// guardAuthMode refuses to start the API with --auth=none unless the operator
// explicitly opts in via OSCTRL_INSECURE_NO_AUTH=1. When the opt-in is set,
// every 60s a loud warning is logged so the deployment cannot drift into
// "auth-off forever" without anyone noticing.
//
// The warning goroutine watches the supplied context so a future graceful
// shutdown path can cancel it cleanly. Today the API has no shutdown signal
// handling so the context never fires — that's acceptable; we get the
// no-leak property for free when shutdown is added.
func guardAuthMode(ctx context.Context, auth string) {
	if auth != config.AuthNone {
		return
	}
	if os.Getenv("OSCTRL_INSECURE_NO_AUTH") != "1" {
		log.Fatal().Msg("auth=none is disabled by default. Set OSCTRL_INSECURE_NO_AUTH=1 to opt in for local development only — every request will be served as super-admin")
	}
	go func() {
		log.Warn().Msg("INSECURE: osctrl-api running with auth=none — every request is served as super-admin. DO NOT use in production")
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Warn().Msg("INSECURE: osctrl-api running with auth=none — every request is served as super-admin. DO NOT use in production")
			}
		}
	}()
}

// Go go!
func osctrlAPIService() {
	// Refuse to run unauthenticated unless the operator explicitly opts in.
	guardAuthMode(context.Background(), flagParams.Service.Auth)
	// Configure forwarding-header trust. Empty (default) means utils.GetIP
	// ignores X-Forwarded-For / X-Real-IP and always uses RemoteAddr, so
	// an internet attacker can't spoof IPs to defeat rate-limits or
	// poison the audit log.
	if tp := strings.TrimSpace(flagParams.Service.TrustedProxies); tp != "" {
		utils.SetTrustedProxies(strings.Split(tp, ","))
		log.Info().Msgf("Trusting forwarding headers from: %s", tp)
	}
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	for {
		db, err = backend.CreateDBManager(flagParams.DB)
		if db != nil {
			log.Info().Msg("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to backend")
			if flagParams.DB.ConnRetry == 0 {
				log.Fatal().Msg("Connection to backend failed and no retry was set")
			}
		}
		log.Info().Msgf("Backend NOT ready! Retrying in %d seconds...\n", flagParams.DB.ConnRetry)
		time.Sleep(time.Duration(flagParams.DB.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Info().Msg("Initializing cache...")
	for {
		redis, err = cache.CreateRedisManager(*flagParams.Redis)
		if redis != nil {
			log.Info().Msg("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to cache")
			if flagParams.Redis.ConnRetry == 0 {
				log.Fatal().Msg("Connection to cache failed and no retry was set")
			}
		}
		log.Info().Msgf("Cache NOT ready! Retrying in %d seconds...\n", flagParams.Redis.ConnRetry)
		time.Sleep(time.Duration(flagParams.Redis.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize users")
	apiUsers = users.CreateUserManager(db.Conn).WithJWT(flagParams.JWT)
	log.Info().Msg("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	geoIPResolver, err := geoip.New(flagParams.Service.GeoIPDBPath)
	if err != nil {
		log.Warn().Err(err).Msg("GeoIP resolver not loaded, country codes will be empty")
		geoIPResolver = nil
	}

	log.Info().Msg("Initialize environment")
	envs = environments.CreateEnvironment(db.Conn)
	envCache := environments.NewRedisEnvCache(*envs, redis.Client)
	log.Info().Msg("Environment cache wired to Redis")
	// DB health monitor: when enabled, pings the DB on a fixed
	// interval and switches EnvCache into stale-serve mode after N
	// consecutive failures, so the API keeps responding to read-only
	// env lookups (used by handlers that hit EnvCache) during a DB
	// outage. Writes still require the DB and will fail. See
	// pkg/backend/health.go.
	var dbHealth *backend.DBHealth
	if flagParams.Service.DBHealthCheck {
		interval := time.Duration(flagParams.Service.DBHealthInterval) * time.Second
		threshold := uint32(flagParams.Service.DBHealthThreshold)
		dbHealth = backend.NewDBHealth(db, interval, threshold)
		dbHealth.Start()
		envCache.SetDBHealth(dbHealth)
		log.Info().
			Dur("interval", interval).
			Uint32("threshold", threshold).
			Msg("DB health monitor enabled — EnvCache will stale-serve on DB outage")
	}
	// Security & compliance posture system (disabled by default)
	var posturemgr *posture.PostureManager
	if flagParams.Service.PostureEnabled {
		posturemgr = posture.NewPostureManager(db.Conn)
		log.Info().Msg("Posture system enabled")
	} else {
		log.Info().Msg("Posture system disabled (enable with --posture-enabled)")
	}
	// Initialize settings
	// Multi-factor authentication for password logins. The manager owns its
	// tables and is always available; WebAuthn additionally needs a relying
	// party id and origin, and stays nil (TOTP-only) when neither the
	// config nor the service host provides one.
	mfamgr := mfa.NewManager(db.Conn)
	var webAuthn *mfa.WebAuthn
	rpID := flagParams.Service.MFARPID
	if rpID == "" {
		rpID = flagParams.Service.Host
	}
	origins := splitAndTrim(flagParams.Service.MFAOrigins)
	if len(origins) == 0 && rpID != "" {
		origins = []string{"https://" + rpID}
	}
	if rpID != "" && len(origins) > 0 {
		webAuthn, err = mfa.NewWebAuthn(mfamgr, rpID, mfaIssuerName(flagParams), origins)
		if err != nil {
			log.Err(err).Msg("WebAuthn disabled — passkeys and security keys will not be offered")
			webAuthn = nil
		} else {
			log.Info().Str("rpid", rpID).Strs("origins", origins).Msg("WebAuthn enabled")
		}
	} else {
		log.Warn().Msg("WebAuthn disabled — set --host or --mfa-rpid to enable passkeys and security keys")
	}
	if flagParams.Service.MFARequired {
		log.Info().Msg("Multi-factor authentication is required for password logins")
	}
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	queriesmgr.Cache = queries.NewQueryDispatchCache(redis.Client, 0)
	log.Info().Msg("Initialize console")
	consolemgr = console.NewManager(db.Conn, queriesmgr)
	log.Info().Msg("Initialize file explorer")
	fileexplorermgr = fileexplorer.NewManager(db.Conn, queriesmgr)
	// Construct the log reader. When the TLS logger ships logs to S3 the
	// osquery_*_data tables are empty, so the API/console/file-explorer
	// read logs back from S3 instead. For every other logger the data
	// lives in the DB and the legacy GORM-backed reader is used.
	var logReader logging.LogReader
	if flagParams.Logger != nil && flagParams.Logger.Type == config.LoggingS3 && flagParams.Logger.S3 != nil {
		log.Info().Msg("Logger is S3 — initializing S3-backed log reader")
		s3Logger, err := logging.CreateLoggerS3(flagParams.Logger.S3)
		if err != nil {
			log.Fatal().Err(err).Msg("Error initializing S3 log reader")
		}
		logReader = logging.NewS3LogReader(s3Logger.Client, s3Logger.S3Config.Bucket)
	} else {
		logReader = logging.NewDBLogReader(db.Conn)
	}
	consolemgr.SetLogReader(logReader)
	fileexplorermgr.SetLogReader(logReader)
	log.Info().Msg("Initialize carves")
	filecarves = carves.CreateFileCarves(db.Conn, flagParams.Carver.Type, nil)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
	log.Info().Msg("Seeding service config from YAML")
	serviceConfigMgr := serviceconfig.NewServiceConfigManager(db.Conn)
	serviceCommandMgr := servicecommands.NewManager(db.Conn)
	// Log sinks manager shares the service-config feature gate: when
	// serviceConfigEnabled is false the routes are not registered and
	// the SPA hides the section. The manager is still constructed so
	// the table is migrated; rows can be edited directly in the DB or
	// YAML and picked up on the next osctrl-tls boot/reload.
	logSinksMgr := logsinks.NewLogSinksManager(db.Conn)
	// Auth providers manager — shares the service-config feature gate.
	authProvidersMgr := authproviders.NewAuthProviderManager(db.Conn)
	if err := authProvidersMgr.Seed(flagParams); err != nil {
		log.Fatal().Err(err).Msg("Error seeding auth providers")
	}
	// Build live providers from the DB. Fail-fast if an enabled
	// provider's IdP is unreachable — same posture as the old
	// InitOIDC/InitSAML calls.
	var authProviderRegistry *handlers.AuthProviderRegistry
	providerEntries, err := authProvidersMgr.BuildProviders(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("Error building auth providers from DB")
	}
	authProviderRegistry = handlers.NewAuthProviderRegistry(providerEntries)
	if err := serviceConfigMgr.Seed(config.ServiceAPI, flagParams, settings.NoEnvironmentID); err != nil {
		log.Fatal().Msgf("Error seeding service config - %v", err)
	}
	log.Info().Msg("Resolving service config from DB")
	if err := serviceConfigMgr.Resolve(config.ServiceAPI, flagParams, settings.NoEnvironmentID); err != nil {
		log.Fatal().Msgf("Error resolving service config - %v", err)
	}
	// Report whether this process can write its own config file. Only this
	// process can know — osctrl-tls runs elsewhere and reports its own.
	if err := serviceConfigMgr.ReportFile(config.ServiceAPI, flagParams.ConfigFilePath()); err != nil {
		log.Err(err).Msg("Error reporting service config file status")
	}
	// Resolve the per-feature enabled flags. They default to true
	// when nil (backwards compat: service-config-enabled controls
	// the master gate, and each sub-feature can be independently
	// disabled by setting its flag to false).
	logSinksEnabled := true
	if flagParams.Service.LogSinksEnabled != nil {
		logSinksEnabled = *flagParams.Service.LogSinksEnabled
	}
	authProvidersEnabled := true
	if flagParams.Service.AuthProvidersEnabled != nil {
		authProvidersEnabled = *flagParams.Service.AuthProvidersEnabled
	}
	if !flagParams.Service.ServiceConfigEnabled {
		log.Info().Msg("Service config API is disabled (enable with --service-config-enabled) — sections are still seeded and resolved, change the service_config rows or the YAML file directly")
	}
	if !logSinksEnabled {
		log.Info().Msg("Log sinks API is disabled (enable with --log-sinks-enabled) — rows can still be changed directly in the database")
	}
	if !authProvidersEnabled {
		log.Info().Msg("Auth providers API is disabled (enable with --auth-providers-enabled) — rows can still be changed directly in the database")
	}
	if flagParams.RateLimits == nil {
		flagParams.RateLimits = config.DefaultRateLimitsPtr()
	}
	if err := config.ValidateRateLimits(*flagParams.RateLimits, "login", "preAuth", "serviceConfigApply"); err != nil {
		log.Fatal().Msgf("Invalid rate limit configuration - %v", err)
	}
	// Initialize audit log manager
	if flagParams.Service.AuditLog {
		log.Info().Msg("Initialize audit log")
	}
	auditLog, err = auditlog.CreateAuditLogManager(db.Conn, serviceName, flagParams.Service.AuditLog)
	if err != nil {
		log.Fatal().Msgf("Error initializing audit log manager - %v", err)
	}
	// Load osquery tables schema (best-effort; an empty slice is fine if the file doesn't exist)
	if flagParams.Osquery.TablesFile != "" {
		log.Info().Msgf("Loading osquery tables from %s", flagParams.Osquery.TablesFile)
		osqueryTables, err = osquery.LoadTables(flagParams.Osquery.TablesFile)
		if err != nil {
			log.Warn().Msgf("Failed to load osquery tables: %v", err)
			osqueryTables = []types.OsqueryTable{}
		}
	}
	// Initialize Admin handlers before router
	log.Info().Msg("Initializing handlers")
	// Initialize the global OIDC provider BEFORE constructing the
	// handlers struct. We need to fail fast if --oidc-enabled is set
	// but discovery fails — running an SPA login page that links to a
	// broken IdP route is worse than refusing to start.
	if flagParams.OIDC != nil && flagParams.OIDC.Enabled {
		log.Info().Msg("OIDC enabled — discovering provider")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := handlers.InitOIDC(ctx, *flagParams.OIDC); err != nil {
			cancel()
			log.Fatal().Err(err).Msg("Can not initialize OIDC")
		}
		cancel()
	}
	// Same fail-fast posture for SAML — refuse to start if metadata
	// fetch fails so we never serve an SPA login button that links
	// to a broken /auth/saml/login route.
	if flagParams.SAML != nil && flagParams.SAML.Enabled {
		log.Info().Msg("SAML enabled — fetching IdP metadata")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := handlers.InitSAML(ctx, *flagParams.SAML, flagParams.SAML.EntityID, flagParams.SAML.ACSURL); err != nil {
			cancel()
			log.Fatal().Err(err).Msg("Can not initialize SAML")
		}
		cancel()
	}

	// Restart channel for the service-config apply endpoint. When the
	// operator clicks "Apply & Restart", the handler signals this channel
	// and the main goroutine shuts down gracefully so the process manager
	// restarts the service with the DB-edited config.
	restartCh := make(chan struct{}, 1)

	// Persisting this service's config file happens in this process — the
	// YAML loader lives here, and no other service can reach the file.
	persistConfig := func() error {
		path := flagParams.ConfigFilePath()
		loaded, err := loadYAMLConfiguration(path)
		if err != nil {
			return fmt.Errorf("reload %s: %w", path, err)
		}
		return serviceConfigMgr.PersistToFile(config.ServiceAPI, path, loadedYAMLToServiceParams(loaded, path), settings.NoEnvironmentID)
	}

	handlersApi = handlers.CreateHandlersApi(
		handlers.WithDB(db.Conn),
		handlers.WithLogReader(logReader),
		handlers.WithEnvs(envs),
		handlers.WithEnvCache(envCache),
		handlers.WithUsers(apiUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithConsole(consolemgr),
		handlers.WithFileExplorer(fileexplorermgr),
		handlers.WithCarves(filecarves),
		handlers.WithSettings(settingsmgr),
		handlers.WithServiceConfig(serviceConfigMgr),
		handlers.WithLogSinks(logSinksMgr),
		handlers.WithAuthProviders(authProviderRegistry, authProvidersMgr),
		handlers.WithServiceConfigEnabled(flagParams.Service.ServiceConfigEnabled),
		handlers.WithLogSinksEnabled(logSinksEnabled),
		handlers.WithAuthProvidersEnabled(authProvidersEnabled),
		handlers.WithServiceCommands(serviceCommandMgr),
		handlers.WithConfigPersist(persistConfig),
		handlers.WithActivityReader(activity.NewRedisStore(redis.Client, activity.DefaultPrefix, activity.DefaultRetentionDays, 8*24*time.Hour)),
		handlers.WithGeoIP(geoIPResolver),
		handlers.WithPosture(posturemgr),
		handlers.WithPostureEnabled(flagParams.Service.PostureEnabled),
		handlers.WithMFA(mfamgr, webAuthn, flagParams.Service.MFARequired, mfaIssuerName(flagParams)),
		handlers.WithVersion(buildVersion),
		handlers.WithName(serviceName),
		handlers.WithAuditLog(auditLog),
		handlers.WithDebugHTTP(flagParams.Debug),
		handlers.WithOsqueryTables(osqueryTables),
		handlers.WithOsqueryValues(*flagParams.Osquery),
		handlers.WithJWTSecret([]byte(flagParams.JWT.JWTSecret)),
		handlers.WithOIDC(flagParams.OIDC != nil && flagParams.OIDC.Enabled),
		handlers.WithSAML(flagParams.SAML != nil && flagParams.SAML.Enabled),
		handlers.WithDBHealth(dbHealth), // nil when DB health monitor disabled
		handlers.WithRestartCh(restartCh),
	)

	// ///////////////////////// API
	log.Info().Msg("Initializing router")
	// Create router for API endpoint
	muxAPI := http.NewServeMux()
	// API: root
	muxAPI.HandleFunc("GET /", handlersApi.RootHandler)
	// API: testing
	muxAPI.HandleFunc("GET "+healthPath, handlersApi.HealthHandler)
	// API: error
	muxAPI.HandleFunc("GET "+errorPath, handlersApi.ErrorHandler)
	// API: forbidden
	muxAPI.HandleFunc("GET "+forbiddenPath, handlersApi.ForbiddenHandler)
	// API: check status
	muxAPI.HandleFunc("GET "+_apiPath(checksNoAuthPath), handlersApi.CheckHandlerNoAuth)

	// ///////////////////////// UNAUTHENTICATED
	// Login is the only password-acceptance surface on the API. By default
	// it is capped to 10 attempts per IP per minute and 429s the rest.
	// Rejections are audit-logged inside the LoginHandler / RateLimit
	// middleware so SoC tooling sees the spray.
	//
	loginLimiter := ratelimit.NewFromConfig(flagParams.RateLimits.Login)
	loginRateLimit := loginLimiter.HTTPMiddleware(ratelimit.KeyByIP, func(r *http.Request, key string) {
		handlersApi.AuditLog.FailedLogin("", utils.GetIP(r), "rate limit exceeded")
	})
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/{env}", loginRateLimit(http.HandlerFunc(handlersApi.LoginHandler)))
	muxAPI.Handle("POST "+_apiPath(apiLoginPath), loginRateLimit(http.HandlerFunc(handlersApi.LoginHandler)))
	// Second factor. Same rate limiter as the password step: an attacker
	// who has the password must not get unlimited guesses at a 6-digit code.
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/mfa", loginRateLimit(http.HandlerFunc(handlersApi.LoginMFAHandler)))
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/mfa/webauthn/begin", loginRateLimit(http.HandlerFunc(handlersApi.LoginMFAWebAuthnBeginHandler)))
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/mfa/webauthn/finish", loginRateLimit(http.HandlerFunc(handlersApi.LoginMFAWebAuthnFinishHandler)))
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/mfa/enroll/begin", loginRateLimit(http.HandlerFunc(handlersApi.LoginMFAEnrollBeginHandler)))
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/mfa/enroll/finish", loginRateLimit(http.HandlerFunc(handlersApi.LoginMFAEnrollFinishHandler)))
	// Read-only pre-auth endpoints (env list for the login picker).
	// The env list is the one piece of data the login page legitimately
	// needs before the user has a session, so it stays pre-auth —
	// rate-limited at 60/min/IP by default to block low-effort scanning probes.
	// React strict-mode / browser reloads easily exceed 10/min during
	// normal use, so the preAuth budget is more permissive than the
	// credential-spray budget on /login.
	preAuthLimiter := ratelimit.NewFromConfig(flagParams.RateLimits.PreAuth)
	preAuthRateLimit := preAuthLimiter.HTTPMiddleware(ratelimit.KeyByIP, nil)
	muxAPI.Handle("GET "+_apiPath(apiLoginPath)+"/environments", preAuthRateLimit(http.HandlerFunc(handlersApi.LoginEnvironmentsHandler)))
	// Auth-methods discovery: the SPA polls this to decide whether to
	// render an "OIDC" button alongside the password form. Read-only,
	// no secrets in the response, pre-auth rate limit.
	muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/methods", preAuthRateLimit(http.HandlerFunc(handlersApi.AuthMethodsHandler)))
	// Logout: unauthenticated by design — an expired-token user
	// must be able to log out without first re-authenticating.
	// Server-side cookie expiry + APIToken revocation happen here.
	// Worst case if forged: invalidates the legitimate user's
	// token, which is exactly what logout should do.
	muxAPI.Handle("POST "+_apiPath("/logout"), preAuthRateLimit(http.HandlerFunc(handlersApi.LogoutHandler)))
	// OIDC login + callback. Registered ONLY when --oidc-enabled is
	// set, so a misconfigured deploy doesn't expose 500-returning
	// stubs. The handlers themselves also guard with `oidcProvider
	// == nil` for defense in depth, but route-level gating keeps the
	// public route table accurate.
	//
	// The login endpoint shares the strict login rate limit (10/min/IP)
	// with the password endpoint — both are credential surfaces from
	// the attacker's POV. Callback uses the looser pre-auth limit
	// because it carries IdP-signed material and is harder to spam
	// usefully.
	if flagParams.OIDC != nil && flagParams.OIDC.Enabled {
		muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/oidc/login", loginRateLimit(http.HandlerFunc(handlersApi.OIDCLoginHandler)))
		muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/oidc/callback", preAuthRateLimit(http.HandlerFunc(handlersApi.OIDCCallbackHandler)))
	}
	// SAML routes follow the OIDC posture: gated by --saml-enabled, login
	// on the strict limiter, ACS on the looser limiter (the SAMLResponse
	// is IdP-signed so spamming the endpoint without a real assertion
	// gets rejected at the crypto layer anyway), metadata pre-auth and
	// public by design (SP metadata is meant to be machine-readable for
	// IdP-side registration).
	if flagParams.SAML != nil && flagParams.SAML.Enabled {
		muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/saml/login", loginRateLimit(http.HandlerFunc(handlersApi.SAMLLoginHandler)))
		muxAPI.Handle("POST "+_apiPath(apiAuthPath)+"/saml/acs", preAuthRateLimit(http.HandlerFunc(handlersApi.SAMLACSHandler)))
		muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/saml/metadata", preAuthRateLimit(http.HandlerFunc(handlersApi.SAMLMetadataHandler)))
	}
	// ///////////////////////// AUTHENTICATED
	// API: check auth
	muxAPI.Handle(
		"GET "+_apiPath(checksAuthPath), handlerAuthCheck(http.HandlerFunc(handlersApi.CheckHandlerAuth), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: deployment feature switches
	muxAPI.Handle(
		"GET "+_apiPath(apiFeaturesPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.FeaturesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: nodes by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/all",
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllNodesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/active",
		handlerAuthCheck(http.HandlerFunc(handlersApi.ActiveNodesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/inactive",
		handlerAuthCheck(http.HandlerFunc(handlersApi.InactiveNodesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/node/{node}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/{env}/delete",
		handlerAuthCheck(http.HandlerFunc(handlersApi.DeleteNodeHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/{env}/tag",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagNodeHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/lookup",
		handlerAuthCheck(http.HandlerFunc(handlersApi.LookupNodeHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: paginated nodes — canonical SPA endpoint
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodesPagedHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	if flagParams.Service.PostureEnabled {
		// API: node posture (security & compliance data)
		muxAPI.Handle(
			"GET "+_apiPath(apiNodesPath)+"/{env}/node/{uuid}/posture",
			handlerAuthCheck(http.HandlerFunc(handlersApi.NodePostureHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiNodesPath)+"/{env}/node/{uuid}/posture/score",
			handlerAuthCheck(http.HandlerFunc(handlersApi.NodePostureScoreHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		// API: posture profiles (predefined check templates)
		muxAPI.Handle(
			"GET "+_apiPath("/posture")+"/profiles",
			handlerAuthCheck(http.HandlerFunc(handlersApi.PostureProfilesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath("/posture")+"/profiles/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.PostureProfileHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	}
	// API: node logs
	muxAPI.Handle(
		"GET "+_apiPath(apiLogsPath)+"/{type}/{env}/{uuid}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeLogsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: cross-env dashboard stats
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.StatsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: fleet-wide osquery version breakdown for dashboard's hygiene panel.
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/osquery-versions",
		handlerAuthCheck(http.HandlerFunc(handlersApi.OsqueryVersionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: per-env activity heatmap (15-min audit-log buckets across N hours).
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvActivityHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: per-node activity heatmap (status/result/query/carve buckets).
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/node/{env}/{uuid}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeActivityHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// Batch variant — accepts ?uuids=a,b,c (up to 100). Returns a map keyed by
	// uuid. Lets the Nodes table render a per-row sparkline without firing N
	// parallel HTTP requests.
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/node-batch/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeActivityBatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: Redis-backed per-node activity series (config + read/write split).
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/node-tiles/{env}/{uuid}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeActivityTilesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: Redis-backed per-node activity tiles batch (Nodes table heatmap).
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/node-tiles-batch/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeActivityTilesBatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: Redis-backed per-env activity series.
	muxAPI.Handle(
		"GET "+_apiPath(apiStatsPath)+"/activity/env-tiles/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvActivityTilesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: queries by environment
	if flagParams.Osquery.Query {
		// Sample-templates library (post-auth). Pre-auth exposure
		// of the SQL-template starter pack uniquely fingerprints
		// the deployment as osctrl and reveals operator-internal
		// data to anonymous callers; both are useless to the
		// SPA's only legitimate consumer (the post-login
		// queries/new form) at pre-auth time.
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/samples",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QuerySamplesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/{env}/list/{target}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueryListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiQueriesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesRunHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/{env}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueryShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/{env}/results/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueryResultsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		// CSV export for query results
		muxAPI.Handle(
			"GET "+_apiPath(apiQueriesPath)+"/{env}/results/csv/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueryResultsCSVHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiAllQueriesPath+"/{env}"),
			handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiQueriesPath)+"/{env}/{action}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesActionHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		if flagParams.Osquery.Console {
			// API: per-node console
			muxAPI.Handle(
				"POST "+_apiPath("/console")+"/{env}/nodes/{uuid}/sessions",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleSessionCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath("/console")+"/{env}/sessions/{session_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleSessionShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"DELETE "+_apiPath("/console")+"/{env}/sessions/{session_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleSessionDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"POST "+_apiPath("/console")+"/{env}/sessions/{session_id}/commands",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleCommandCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath("/console")+"/{env}/sessions/{session_id}/commands/{command_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleCommandShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath("/console")+"/{env}/sessions/{session_id}/commands/{command_id}/results",
				handlerAuthCheck(http.HandlerFunc(handlersApi.ConsoleCommandResultsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		}
		if flagParams.Osquery.FileExplorer {
			// API: per-node file explorer
			muxAPI.Handle(
				"POST "+_apiPath(apiFileExplorerPath)+"/{env}/nodes/{uuid}/sessions",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerSessionCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerSessionShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"DELETE "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerSessionDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"POST "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}/list",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"POST "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}/stat",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerStatHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}/requests/{request_id}",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerRequestShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}/requests/{request_id}/results",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerRequestResultsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
			muxAPI.Handle(
				"GET "+_apiPath(apiFileExplorerPath)+"/{env}/sessions/{session_id}/requests/{request_id}/metadata",
				handlerAuthCheck(http.HandlerFunc(handlersApi.FileExplorerPrimingResultsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		}
		// API: saved queries (Track 4)
		muxAPI.Handle(
			"GET "+_apiPath(apiSavedQueriesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.SavedQueriesListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiSavedQueriesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.SavedQueryCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"PATCH "+_apiPath(apiSavedQueriesPath)+"/{env}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.SavedQueryUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"DELETE "+_apiPath(apiSavedQueriesPath)+"/{env}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.SavedQueryDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	}
	// API: osquery schema tables (globally available to authenticated users)
	muxAPI.Handle(
		"GET "+_apiPath(apiOsqueryPath)+"/tables",
		handlerAuthCheck(http.HandlerFunc(handlersApi.OsqueryTablesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: carves by environment
	if flagParams.Osquery.Carve {
		// Sample carve-targets library (post-auth). The carve-path
		// list is a shopping list of high-value exfiltration
		// locations (/etc/passwd, \Windows\System32\config\SAM,
		// browser keychains, etc.) that anonymous callers have no
		// legitimate reason to see.
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/samples",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveSamplesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/{env}/queries/{target}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveQueriesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/{env}/list",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiCarvesPath)+"/{env}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesRunHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/{env}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveShowHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiCarvesPath)+"/{env}/archive/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarveArchiveHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiCarvesPath)+"/{env}/{action}/{name}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesActionHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	}
	// API: users
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath)+"/me",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MeHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiUsersPath)+"/me",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MePatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/me/password",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MePasswordHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath)+"/{username}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.UserHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.UsersHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath)+"/{username}/permissions",
		handlerAuthCheck(http.HandlerFunc(handlersApi.GetUserPermissionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/{username}/permissions",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SetUserPermissionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/{username}/permissions/all",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SetUserPermissionsAllHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/{username}/token/refresh",
		handlerAuthCheck(http.HandlerFunc(handlersApi.RefreshUserTokenHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"DELETE "+_apiPath(apiUsersPath)+"/{username}/token",
		handlerAuthCheck(http.HandlerFunc(handlersApi.DeleteUserTokenHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/{username}/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.UserActionHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: platforms
	muxAPI.Handle(
		"GET "+_apiPath(apiPlatformsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.PlatformsEnvHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: environments
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/actions",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvActionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))

	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/map/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentMapHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}/configuration/assembled",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvConfigurationHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/cert",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvCertUploadHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollActionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvRemoveHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvRemoveActionsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: environments CRUD + config (Track 8)
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiEnvironmentsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"DELETE "+_apiPath(apiEnvironmentsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// Env config routes use a `/config/{env}` shape (literal in segment 1) so
	// they cannot register-conflict with `/map/{target}` registered above. A
	// `/{env}/config` shape would put a wildcard in segment 1 — Go's ServeMux
	// refuses to accept it alongside `/map/{target}` since neither pattern
	// strictly dominates the other.
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/config/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentConfigHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiEnvironmentsPath)+"/config/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentConfigPatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiEnvironmentsPath)+"/intervals/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentIntervalsPatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiEnvironmentsPath)+"/expiration/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentExpirationPatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: environment packages (multi-architecture)
	// Uses /packages/{env} shape (literal in segment 1) to avoid conflicts
	// with /map/{target} — same pattern as /config/{env} and /intervals/{env}.
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/packages/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvPackagesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/packages/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvPackageAddHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"DELETE "+_apiPath(apiEnvironmentsPath)+"/packages/{env}/{id}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvPackageRemoveHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"PATCH "+_apiPath(apiEnvironmentsPath)+"/packages/{env}/{id}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvPackageUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: tags by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllTagsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagsEnvHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath)+"/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagEnvHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiTagsPath)+"/{env}/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagsActionHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: settings by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: settings PATCH (Track 9)
	muxAPI.Handle(
		"PATCH "+_apiPath(apiSettingsPath)+"/{service}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingPatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// Rate-limit the restart/apply endpoints to 3 per 10 minutes per IP
	// by default — strict enough to prevent brute-forcing restarts,
	// generous enough for an operator to retry after a failed restart.
	// Rejections are audit-logged so SoC tooling sees attempted abuse.
	restartLimiter := ratelimit.NewFromConfig(flagParams.RateLimits.ServiceConfigApply)
	restartRateLimit := restartLimiter.HTTPMiddleware(ratelimit.KeyByIP, func(r *http.Request, key string) {
		handlersApi.AuditLog.SettingsAction("", fmt.Sprintf("service-config apply rate limit exceeded from %s", key), utils.GetIP(r))
	})

	// API: service config. Opt-in via --service-config-enabled. Seeding
	// YAML into the service_config rows and resolving them at startup
	// happen either way, so the rows stay the values the services run on
	// and can be changed directly in the database.
	if flagParams.Service.ServiceConfigEnabled {
		muxAPI.Handle(
			"GET "+_apiPath(apiServiceConfigPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiServiceConfigPath)+"/commands/{command_id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceCommandHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiServiceConfigPath)+"/{service}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigServiceHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiServiceConfigPath)+"/status/{service}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigStatusHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiServiceConfigPath)+"/{service}/{section}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigSectionHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"PUT "+_apiPath(apiServiceConfigPath)+"/{service}/{section}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiServiceConfigPath)+"/apply",
			restartRateLimit(handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigApplyHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret)))
		muxAPI.Handle(
			"POST "+_apiPath(apiServiceConfigPath)+"/persist",
			restartRateLimit(handlerAuthCheck(http.HandlerFunc(handlersApi.ServiceConfigPersistHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret)))
	}

	// API: log sinks. Independently gated by --log-sinks-enabled. Does
	// NOT require --service-config-enabled. The apply endpoint reuses
	// the same restart limiter since a log sink reload is the same class
	// of privileged operation.
	if logSinksEnabled {
		muxAPI.Handle(
			"GET "+_apiPath(apiLogSinksPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiLogSinksPath)+"/types",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksTypesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiLogSinksPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksGetHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiLogSinksPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"PUT "+_apiPath(apiLogSinksPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"DELETE "+_apiPath(apiLogSinksPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiLogSinksPath)+"/{id}/revert",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksRevertHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiLogSinksPath)+"/clone",
			handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksCloneHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiLogSinksPath)+"/apply",
			restartRateLimit(handlerAuthCheck(http.HandlerFunc(handlersApi.LogSinksApplyHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret)))
	}

	// API: auth providers. Independently gated by
	// --auth-providers-enabled. Does NOT require
	// --service-config-enabled.
	if authProvidersEnabled {
		muxAPI.Handle(
			"GET "+_apiPath(apiAuthProvidersPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersListHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiAuthProvidersPath)+"/types",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersTypesHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"GET "+_apiPath(apiAuthProvidersPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersGetHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiAuthProvidersPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersCreateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"PUT "+_apiPath(apiAuthProvidersPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersUpdateHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"DELETE "+_apiPath(apiAuthProvidersPath)+"/{id}",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiAuthProvidersPath)+"/{id}/revert",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersRevertHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiAuthProvidersPath)+"/test",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersTestHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiAuthProvidersPath)+"/fetch-metadata",
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersFetchMetadataHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
		muxAPI.Handle(
			"POST "+_apiPath(apiAuthProvidersPath)+"/apply",
			restartRateLimit(handlerAuthCheck(http.HandlerFunc(handlersApi.AuthProvidersApplyHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret)))
	}
	// API: multi-factor enrollment for the calling user
	muxAPI.Handle(
		"GET "+_apiPath(apiMFAPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFAStatusHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiMFAPath)+"/totp",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFATOTPBeginHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiMFAPath)+"/totp/verify",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFATOTPVerifyHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"DELETE "+_apiPath(apiMFAPath)+"/totp",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFATOTPDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiMFAPath)+"/recovery",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFARecoveryHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiMFAPath)+"/webauthn",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFAWebAuthnBeginHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiMFAPath)+"/webauthn/verify",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFAWebAuthnFinishHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"DELETE "+_apiPath(apiMFAPath)+"/webauthn/{id}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.MFAWebAuthnDeleteHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: audit log
	if flagParams.Service.AuditLog {
		muxAPI.Handle(
			"GET "+_apiPath(apiAuditLogsPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuditLogsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	}
	// Launch listeners for API server. The server runs in a goroutine so
	// the main goroutine can wait on the restart channel and trigger a
	// graceful shutdown when the operator applies config changes.
	serviceListener := flagParams.Service.Listener + ":" + strconv.Itoa(flagParams.Service.Port)
	tlsTermination := flagParams.TLS != nil && flagParams.TLS.Termination
	srv := &http.Server{
		Addr:    serviceListener,
		Handler: muxAPI,
	}
	if tlsTermination {
		srv.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
	}
	serverErr := make(chan error, 1)
	go func() {
		log.Info().Msgf("%s v%s - HTTP%s listening %s", serviceName, buildVersion,
			map[bool]string{true: "S", false: ""}[tlsTermination], serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if tlsTermination {
			serverErr <- srv.ListenAndServeTLS(flagParams.TLS.CertificateFile, flagParams.TLS.KeyFile)
		} else {
			serverErr <- srv.ListenAndServe()
		}
	}()
	// Wait for either a server error or a restart signal.
	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Msgf("ListenAndServe: %v", err)
		}
	case <-restartCh:
		log.Info().Msg("Service config apply triggered — exiting for restart")
		// Exit with code 1 so process managers (systemd, docker, k8s) and
		// dev tools like air restart the process. A clean exit (0) is not
		// restarted by air (the dev hot-reload tool), which treats exit 0
		// as "done, no restart needed." Using exit 1 ensures restart in
		// both dev (air) and production (systemd/k8s) environments.
		os.Exit(1)
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(ctx context.Context, cmd *cli.Command) error {
	// Load configuration if external YAML config file is used
	if flagParams.ConfigFlag {
		serviceConfiguration, err = loadYAMLConfiguration(flagParams.ServiceConfigFile)
		if err != nil {
			return fmt.Errorf("error loading %s - %w", flagParams.ServiceConfigFile, err)
		}
		flagParams = loadedYAMLToServiceParams(serviceConfiguration, flagParams.ServiceConfigFile)
	}
	return nil
}

func initializeLoggers(cfg config.YAMLConfigurationService) {
	// Set the log level
	switch strings.ToLower(cfg.LogLevel) {
	case config.LogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case config.LogLevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case config.LogLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case config.LogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	// Set the log format
	switch strings.ToLower(cfg.LogFormat) {
	case config.LogFormatJSON:
		log.Logger = log.With().Caller().Logger()
	case config.LogFormatConsole:
		zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
			return filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: logging.LoggerTimeFormat}).With().Caller().Logger()
	default:
		log.Logger = log.With().Caller().Logger()
	}
}

// @title osctrl API
// @version 0.5.6
// @description API service for osctrl, a fast and efficient osquery management solution.
// @termsOfService https://github.com/jmpsec/osctrl
// @contact.name osctrl
// @contact.url https://github.com/jmpsec/osctrl
// @license.name MIT
// @license.url https://github.com/jmpsec/osctrl/blob/master/LICENSE
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	// Initiate CLI and parse arguments
	app = &cli.Command{
		Name:        serviceName,
		Usage:       appDescription,
		Version:     buildVersion,
		Description: appDescription,
		Flags: append(flags, &cli.BoolFlag{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Print version information",
			Action: func(ctx context.Context, cmd *cli.Command, b bool) error {
				if b {
					fmt.Printf("%s version=%s commit=%s date=%s\n", serviceName, buildVersion, buildCommit, buildDate)
					os.Exit(0)
				}
				return nil
			},
		}),
		HideVersion: true,
		Commands: []*cli.Command{
			{
				Name: "help",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cli.ShowAppHelpAndExit(cmd, 2)
					return nil
				},
			},
			{
				Name:    "config-validate",
				Aliases: []string{"config-verify"},
				Usage:   "Validate YAML configuration file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "Path to the YAML configuration file to validate",
						Value:   "config/" + config.ServiceAPI + ".yml",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					file := cmd.String("file")
					if file == "" {
						return fmt.Errorf("no configuration file provided")
					}
					_, err := loadYAMLConfiguration(file)
					if err != nil {
						return fmt.Errorf("❌ YAML configuration %s is invalid: %w", file, err)
					}
					fmt.Printf("✅ YAML configuration %s is valid.\n", file)
					return nil
				},
			},
			{
				Name:  "config-generate",
				Usage: "Generate an example configuration file using the current flag values",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Value:   "config/" + config.ServiceAPI + ".yml",
						Usage:   "File path to write the generated configuration",
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"F"},
						Usage:   "Overwrite the output file if it already exists",
						Value:   false,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					file := cmd.String("file")
					if err := config.GenerateAPIConfigFile(file, flagParams, cmd.Bool("force")); err != nil {
						return err
					}
					fmt.Printf("Example configuration written to %s.\n", file)
					return nil
				},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if err := cliAction(ctx, cmd); err != nil {
				return err
			}
			// Initialize service logger
			initializeLoggers(*flagParams.Service)
			// Analyze version and compare with the latest release, runs in a separate goroutine to not delay the service startup
			go checkLatestRelease()
			// Run the service
			osctrlAPIService()
			return nil
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("app.Run error: %s", err.Error())
		os.Exit(1)
	}
}
