package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/api/handlers"
	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/cache"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"

	"github.com/spf13/viper"
)

const (
	// Project name
	projectName = "osctrl"
	// Service name
	serviceName = projectName + "-" + settings.ServiceAPI
	// Service version
	serviceVersion = version.OsctrlVersion
	// Service description
	serviceDescription = "API service for osctrl"
	// Application description
	appDescription = serviceDescription + ", a fast and efficient osquery management"
	// Default service configuration file
	defConfigurationFile = "config/" + settings.ServiceAPI + ".json"
	// Default DB configuration file
	defDBConfigurationFile = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile = "config/redis.json"
	// Default TLS certificate file
	defTLSCertificateFile = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile = "config/tls.key"
	// Default JWT configuration file
	defJWTConfigurationFile = "config/jwt.json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// Paths
const (
	// HTTP health path
	healthPath = "/health"
	// HTTP errors path
	errorPath     = "/error"
	forbiddenPath = "/forbidden"
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
)

// Global variables
var (
	err               error
	apiConfigValues   types.JSONConfigurationAPI
	apiConfig         types.JSONConfigurationAPI
	dbConfigValues    backend.JSONConfigurationDB
	dbConfig          backend.JSONConfigurationDB
	redisConfigValues cache.JSONConfigurationRedis
	redisConfig       cache.JSONConfigurationRedis
	jwtConfigValues   types.JSONConfigurationJWT
	jwtConfig         types.JSONConfigurationJWT
	db                *backend.DBManager
	redis             *cache.RedisManager
	apiUsers          *users.UserManager
	tagsmgr           *tags.TagManager
	settingsmgr       *settings.Settings
	envs              *environments.Environment
	envsmap           environments.MapEnvironments
	settingsmap       settings.MapSettings
	nodesmgr          *nodes.NodeManager
	queriesmgr        *queries.Queries
	filecarves        *carves.Carves
	apiMetrics        *metrics.Metrics
	handlersApi       *handlers.HandlersApi
	app               *cli.App
	flags             []cli.Flag
)

// Variables for flags
var (
	configFlag        bool
	serviceConfigFile string
	redisConfigFile   string
	dbFlag            bool
	redisFlag         bool
	dbConfigFile      string
	loggerValue       string
	jwtFlag           bool
	jwtConfigFile     string
	tlsServer         bool
	tlsCertFile       string
	tlsKeyFile        string
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	settings.AuthNone: true,
	settings.AuthJWT:  true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file, service string) (types.JSONConfigurationAPI, error) {
	var cfg types.JSONConfigurationAPI
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// API values
	apiRaw := viper.Sub(service)
	if apiRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", service, file)
	}
	if err := apiRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("invalid auth method: '%s'", cfg.Auth)
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via JSON file",
			EnvVars:     []string{"SERVICE_CONFIG"},
			Destination: &configFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       defConfigurationFile,
			Usage:       "Load service configuration from `FILE`",
			EnvVars:     []string{"SERVICE_CONFIG_FILE"},
			Destination: &serviceConfigFile,
		},
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &apiConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9002",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &apiConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "log-level",
			Value:       types.LogLevelInfo,
			Usage:       "Log level for the service",
			EnvVars:     []string{"SERVICE_LOG_LEVEL"},
			Destination: &apiConfigValues.LogLevel,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Value:       types.LogFormatJSON,
			Usage:       "Log format for the service",
			EnvVars:     []string{"SERVICE_LOG_FORMAT"},
			Destination: &apiConfigValues.LogFormat,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &apiConfigValues.Auth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &apiConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingNone,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &loggerValue,
		},
		&cli.BoolFlag{
			Name:        "redis",
			Aliases:     []string{"r"},
			Value:       false,
			Usage:       "Provide redis configuration via JSON file",
			EnvVars:     []string{"REDIS_CONFIG"},
			Destination: &redisFlag,
		},
		&cli.StringFlag{
			Name:        "redis-file",
			Aliases:     []string{"R"},
			Value:       defRedisConfigurationFile,
			Usage:       "Load redis configuration from `FILE`",
			EnvVars:     []string{"REDIS_CONFIG_FILE"},
			Destination: &redisConfigFile,
		},
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			EnvVars:     []string{"REDIS_CONNECTION_STRING"},
			Destination: &redisConfigValues.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			EnvVars:     []string{"REDIS_HOST"},
			Destination: &redisConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "redis-port",
			Value:       "6379",
			Usage:       "Redis port to be connected to",
			EnvVars:     []string{"REDIS_PORT"},
			Destination: &redisConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			EnvVars:     []string{"REDIS_PASS"},
			Destination: &redisConfigValues.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			EnvVars:     []string{"REDIS_DB"},
			Destination: &redisConfigValues.DB,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"REDIS_CONN_RETRY"},
			Destination: &redisConfigValues.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &dbFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &dbConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbConfigValues.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbConfigValues.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbConfigValues.Password,
		},
		&cli.StringFlag{
			Name:        "db-sslmode",
			Value:       "disable",
			Usage:       "SSL native support to encrypt the connection to the backend",
			EnvVars:     []string{"DB_SSLMODE"},
			Destination: &dbConfigValues.SSLMode,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbConfigValues.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbConfigValues.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConfigValues.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"DB_CONN_RETRY"},
			Destination: &dbConfigValues.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			EnvVars:     []string{"TLS_SERVER"},
			Destination: &tlsServer,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       defTLSCertificateFile,
			Usage:       "TLS termination certificate from `FILE`",
			EnvVars:     []string{"TLS_CERTIFICATE"},
			Destination: &tlsCertFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       defTLSKeyFile,
			Usage:       "TLS termination private key from `FILE`",
			EnvVars:     []string{"TLS_KEY"},
			Destination: &tlsKeyFile,
		},
		&cli.BoolFlag{
			Name:        "jwt",
			Aliases:     []string{"j"},
			Value:       false,
			Usage:       "Provide JWT configuration via JSON file",
			EnvVars:     []string{"JWT_CONFIG"},
			Destination: &jwtFlag,
		},
		&cli.StringFlag{
			Name:        "jwt-file",
			Value:       defJWTConfigurationFile,
			Usage:       "Load JWT configuration from `FILE`",
			EnvVars:     []string{"JWT_CONFIG_FILE"},
			Destination: &jwtConfigFile,
		},
		&cli.StringFlag{
			Name:        "jwt-secret",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"JWT_SECRET"},
			Destination: &jwtConfigValues.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       3,
			Usage:       "Maximum amount of hours for the tokens to expire",
			EnvVars:     []string{"JWT_EXPIRE"},
			Destination: &jwtConfigValues.HoursToExpire,
		},
	}

}

// Go go!
func osctrlAPIService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	for {
		db, err = backend.CreateDBManager(dbConfig)
		if db != nil {
			log.Info().Msg("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to backend")
			if dbConfig.ConnRetry == 0 {
				log.Fatal().Msg("Connection to backend failed and no retry was set")
			}
		}
		log.Info().Msgf("Backend NOT ready! Retrying in %d seconds...\n", dbConfig.ConnRetry)
		time.Sleep(time.Duration(dbConfig.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Info().Msg("Initializing cache...")
	for {
		redis, err = cache.CreateRedisManager(redisConfig)
		if redis != nil {
			log.Info().Msg("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to cache")
			if redisConfig.ConnRetry == 0 {
				log.Fatal().Msg("Connection to cache failed and no retry was set")
			}
		}
		log.Info().Msgf("Cache NOT ready! Retrying in %d seconds...\n", redisConfig.ConnRetry)
		time.Sleep(time.Duration(redisConfig.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize users")
	apiUsers = users.CreateUserManager(db.Conn, &jwtConfig)
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
	filecarves = carves.CreateFileCarves(db.Conn, apiConfig.Carver, nil)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
	log.Info().Msg("Loading service metrics")
	apiMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading metrics - %v", err)
	}
	// Ticker to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Info().Msg("Initialize environments refresh")
	// Refresh environments as soon as service starts
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceAPI)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			envsmap = refreshEnvironments()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// Ticker to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	// Refresh settings as soon as the service starts
	log.Info().Msg("Initialize settings refresh")
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceAPI)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	// Initialize Admin handlers before router
	log.Info().Msg("Initializing handlers")
	handlersApi = handlers.CreateHandlersApi(
		handlers.WithDB(db.Conn),
		handlers.WithEnvs(envs),
		handlers.WithUsers(apiUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(filecarves),
		handlers.WithSettings(settingsmgr),
		handlers.WithMetrics(apiMetrics),
		handlers.WithCache(redis),
		handlers.WithVersion(serviceVersion),
		handlers.WithName(serviceName),
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

	// ///////////////////////// UNAUTHENTICATED
	muxAPI.Handle("POST "+_apiPath(apiLoginPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.LoginHandler)))
	// ///////////////////////// AUTHENTICATED
	// API: nodes by environment
	muxAPI.Handle("GET "+_apiPath(apiNodesPath)+"/{env}/all", handlerAuthCheck(http.HandlerFunc(handlersApi.AllNodesHandler)))
	muxAPI.Handle("GET "+_apiPath(apiNodesPath)+"/{env}/active", handlerAuthCheck(http.HandlerFunc(handlersApi.ActiveNodesHandler)))
	muxAPI.Handle("GET "+_apiPath(apiNodesPath)+"/{env}/inactive", handlerAuthCheck(http.HandlerFunc(handlersApi.InactiveNodesHandler)))
	muxAPI.Handle("GET "+_apiPath(apiNodesPath)+"/{env}/node/{node}", handlerAuthCheck(http.HandlerFunc(handlersApi.NodeHandler)))
	muxAPI.Handle("POST "+_apiPath(apiNodesPath)+"/{env}/delete", handlerAuthCheck(http.HandlerFunc(handlersApi.DeleteNodeHandler)))
	// API: queries by environment
	muxAPI.Handle("GET "+_apiPath(apiQueriesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler)))
	muxAPI.Handle("GET "+_apiPath(apiQueriesPath)+"/{env}/list/{target}", handlerAuthCheck(http.HandlerFunc(handlersApi.QueryListHandler)))
	muxAPI.Handle("POST "+_apiPath(apiQueriesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesRunHandler)))
	muxAPI.Handle("GET "+_apiPath(apiQueriesPath)+"/{env}/{name}", handlerAuthCheck(http.HandlerFunc(handlersApi.QueryShowHandler)))
	muxAPI.Handle("GET "+_apiPath(apiQueriesPath)+"/{env}/results/{name}", handlerAuthCheck(http.HandlerFunc(handlersApi.QueryResultsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiAllQueriesPath+"/{env}"), handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler)))
	muxAPI.Handle("POST "+_apiPath(apiQueriesPath)+"/{env}/{action}/{name}", handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesActionHandler)))
	// API: carves by environment
	muxAPI.Handle("GET "+_apiPath(apiCarvesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.CarveShowHandler)))
	muxAPI.Handle("GET "+_apiPath(apiCarvesPath)+"/{env}/queries/{target}", handlerAuthCheck(http.HandlerFunc(handlersApi.CarveQueriesHandler)))
	muxAPI.Handle("GET "+_apiPath(apiCarvesPath)+"/{env}/list", handlerAuthCheck(http.HandlerFunc(handlersApi.CarveListHandler)))
	muxAPI.Handle("POST "+_apiPath(apiCarvesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesRunHandler)))
	muxAPI.Handle("GET "+_apiPath(apiCarvesPath)+"/{env}/{name}", handlerAuthCheck(http.HandlerFunc(handlersApi.CarveShowHandler)))
	muxAPI.Handle("POST "+_apiPath(apiCarvesPath)+"/{env}/{action}/{name}", handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesActionHandler)))
	// API: users
	muxAPI.Handle("GET "+_apiPath(apiUsersPath)+"/{username}", handlerAuthCheck(http.HandlerFunc(handlersApi.UserHandler)))
	muxAPI.Handle("GET "+_apiPath(apiUsersPath), handlerAuthCheck(http.HandlerFunc(handlersApi.UsersHandler)))
	// API: platforms
	muxAPI.Handle("GET "+_apiPath(apiPlatformsPath), handlerAuthCheck(http.HandlerFunc(handlersApi.PlatformsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiPlatformsPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.PlatformsEnvHandler)))
	// API: environments
	muxAPI.Handle("GET "+_apiPath(apiEnvironmentsPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentHandler)))
	muxAPI.Handle("GET "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{target}", handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollHandler)))
	muxAPI.Handle("POST "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{action}", handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollActionsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{target}", handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentHandler)))
	muxAPI.Handle("POST "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{action}", handlerAuthCheck(http.HandlerFunc(handlersApi.EnvRemoveActionsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiEnvironmentsPath), handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentsHandler)))
	// API: tags by environment
	muxAPI.Handle("GET "+_apiPath(apiTagsPath), handlerAuthCheck(http.HandlerFunc(handlersApi.AllTagsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiTagsPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.TagsEnvHandler)))
	muxAPI.Handle("POST "+_apiPath(apiTagsPath)+"/{env}/{action}", handlerAuthCheck(http.HandlerFunc(handlersApi.TagsActionHandler)))
	// API: settings by environment
	muxAPI.Handle("GET "+_apiPath(apiSettingsPath), handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsHandler)))
	muxAPI.Handle("GET "+_apiPath(apiSettingsPath)+"/{service}", handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceHandler)))
	muxAPI.Handle("GET "+_apiPath(apiSettingsPath)+"/{service}/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvHandler)))
	muxAPI.Handle("GET "+_apiPath(apiSettingsPath)+"/{service}/json", handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceJSONHandler)))
	muxAPI.Handle("GET "+_apiPath(apiSettingsPath)+"/{service}/json/{env}", handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvJSONHandler)))

	// Launch listeners for API server
	serviceListener := apiConfig.Listener + ":" + apiConfig.Port
	if tlsServer {
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
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		if err := http.ListenAndServe(serviceListener, muxAPI); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if configFlag {
		apiConfig, err = loadConfiguration(serviceConfigFile, settings.ServiceAPI)
		if err != nil {
			return fmt.Errorf("failed to load service configuration %s - %s", serviceConfigFile, err.Error())
		}
	} else {
		apiConfig = apiConfigValues
	}
	// Load DB configuration if external JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("failed to load DB configuration - %s", err.Error())
		}
	} else {
		dbConfig = dbConfigValues
	}
	// Load redis configuration if external JSON config file is used
	if redisFlag {
		redisConfig, err = cache.LoadConfiguration(redisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("failed to load redis configuration - %s", err.Error())
		}
	} else {
		redisConfig = redisConfigValues
	}
	// Load JWT configuration if external JWT JSON config file is used
	if jwtFlag {
		jwtConfig, err = loadJWTConfiguration(jwtConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load JWT configuration - %s", err.Error())
		}
	} else {
		jwtConfig = jwtConfigValues
	}
	return nil
}

func initializeLogger(logLevel, logFormat string) {

	switch strings.ToLower(logLevel) {
	case types.LogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case types.LogLevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case types.LogLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case types.LogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	switch strings.ToLower(logFormat) {
	case types.LogFormatJSON:
		log.Logger = log.With().Caller().Logger()
	case types.LogFormatConsole:
		zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
			return filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02T15:04:05.999Z07:00"}).With().Caller().Logger()
	default:
		log.Logger = log.With().Caller().Logger()
	}

}

func main() {
	// Initiate CLI and parse arguments
	app = cli.NewApp()
	app.Name = serviceName
	app.Usage = appDescription
	app.Version = serviceVersion
	app.Description = appDescription
	app.Flags = flags
	// Define this command for help to exit when help flag is passed
	app.Commands = []*cli.Command{
		{
			Name: "help",
			Action: func(c *cli.Context) error {
				cli.ShowAppHelpAndExit(c, 0)
				return nil
			},
		},
	}
	app.Action = cliAction
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("app.Run error: %s", err.Error())
		os.Exit(1)
	}

	// Initialize service logger
	initializeLogger(apiConfig.LogLevel, apiConfig.LogFormat)

	// Run the service
	osctrlAPIService()
}
