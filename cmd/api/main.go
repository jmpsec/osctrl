package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/cmd/api/handlers"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osquery"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/ratelimit"
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
		Debug: &config.YAMLConfigurationDebug{},
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
	log.Info().Msg("Initialize environment")
	envs = environments.CreateEnvironment(db.Conn)
	// Initialize settings
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Info().Msg("Initialize carves")
	filecarves = carves.CreateFileCarves(db.Conn, flagParams.Carver.Type, nil)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
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

	handlersApi = handlers.CreateHandlersApi(
		handlers.WithDB(db.Conn),
		handlers.WithEnvs(envs),
		handlers.WithUsers(apiUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(filecarves),
		handlers.WithSettings(settingsmgr),
		handlers.WithCache(redis),
		handlers.WithVersion(buildVersion),
		handlers.WithName(serviceName),
		handlers.WithAuditLog(auditLog),
		handlers.WithDebugHTTP(flagParams.Debug),
		handlers.WithOsqueryTables(osqueryTables),
		handlers.WithOsqueryValues(*flagParams.Osquery),
		handlers.WithJWTSecret([]byte(flagParams.JWT.JWTSecret)),
		handlers.WithOIDC(flagParams.OIDC != nil && flagParams.OIDC.Enabled),
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
	// Login is the only password-acceptance surface on the API. Cap to
	// 10 attempts per IP per minute (token-bucket; bursts of 10, refill
	// at 1/6s) and 429 the rest. Rejections are audit-logged inside the
	// LoginHandler / RateLimit middleware so SoC tooling sees the spray.
	//
	loginLimiter := ratelimit.New(10, time.Minute, 10*time.Minute)
	loginRateLimit := loginLimiter.HTTPMiddleware(ratelimit.KeyByIP, func(r *http.Request, key string) {
		handlersApi.AuditLog.FailedLogin("", utils.GetIP(r), "rate limit exceeded")
	})
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/{env}", loginRateLimit(http.HandlerFunc(handlersApi.LoginHandler)))
	// Read-only pre-auth endpoints (env list for the login picker, sample
	// query/carve starter packs). These reveal no secrets and aren't a
	// brute-force vector, so they get a much more permissive limiter — the
	// SPA legitimately fetches them on every login-page render, and React
	// strict-mode / browser reloads easily exceed a 10/min budget. We still
	// rate-limit to block low-effort scanning probes, just at 60/min/IP.
	preAuthLimiter := ratelimit.New(60, time.Minute, 10*time.Minute)
	preAuthRateLimit := preAuthLimiter.HTTPMiddleware(ratelimit.KeyByIP, nil)
	muxAPI.Handle("GET "+_apiPath(apiLoginPath)+"/environments", preAuthRateLimit(http.HandlerFunc(handlersApi.LoginEnvironmentsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiQueriesPath)+"/samples", preAuthRateLimit(http.HandlerFunc(handlersApi.QuerySamplesHandler)))
	muxAPI.Handle("GET "+_apiPath(apiCarvesPath)+"/samples", preAuthRateLimit(http.HandlerFunc(handlersApi.CarveSamplesHandler)))
	// Auth-methods discovery: the SPA polls this to decide whether to
	// render an "OIDC" button alongside the password form. Read-only,
	// no secrets in the response, pre-auth rate limit.
	muxAPI.Handle("GET "+_apiPath(apiAuthPath)+"/methods", preAuthRateLimit(http.HandlerFunc(handlersApi.AuthMethodsHandler)))
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
	// ///////////////////////// AUTHENTICATED
	// API: check auth
	muxAPI.Handle(
		"GET "+_apiPath(checksAuthPath), handlerAuthCheck(http.HandlerFunc(handlersApi.CheckHandlerAuth), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
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
	// API: queries by environment
	if flagParams.Osquery.Query {
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
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/json",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceJSONHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/json/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvJSONHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: settings PATCH (Track 9)
	muxAPI.Handle(
		"PATCH "+_apiPath(apiSettingsPath)+"/{service}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingPatchHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	// API: audit log
	if flagParams.Service.AuditLog {
		muxAPI.Handle(
			"GET "+_apiPath(apiAuditLogsPath),
			handlerAuthCheck(http.HandlerFunc(handlersApi.AuditLogsHandler), flagParams.Service.Auth, flagParams.JWT.JWTSecret))
	}
	// Launch listeners for API server
	serviceListener := flagParams.Service.Listener + ":" + strconv.Itoa(flagParams.Service.Port)
	if flagParams.TLS.Termination {
		cfg := &tls.Config{
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
		srv := &http.Server{
			Addr:         serviceListener,
			Handler:      muxAPI,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := srv.ListenAndServeTLS(flagParams.TLS.CertificateFile, flagParams.TLS.KeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := http.ListenAndServe(serviceListener, muxAPI); err != nil {
			log.Fatal().Msgf("ListenAndServe: %v", err)
		}
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
