package main

import (
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/jmpsec/osctrl/admin/handlers"
	"github.com/jmpsec/osctrl/admin/sessions"
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
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

// Constants for the service
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAdmin
	// Service version
	serviceVersion string = version.OsctrlVersion
	// Service description
	serviceDescription string = "Admin service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// Paths
const (
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle Login
	loginPath string = "/login"
	// Default endpoint to handle Logout
	logoutPath string = "/logout"
	// Default endpoint to handle HTTP(500) errors
	errorPath string = "/error"
	// Default endpoint to handle Forbidden(403) errors
	forbiddenPath string = "/forbidden"
	// Default endpoint for favicon
	faviconPath string = "/favicon.ico"
)

// Configuration
const (
	// Default SAML configuration file
	defSAMLConfigurationFile string = "config/saml.json"
	// Default JWT configuration file
	defJWTConfigurationFile string = "config/jwt.json"
	// Default service configuration file
	defConfigurationFile string = "config/" + settings.ServiceAdmin + ".json"
	// Default DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile string = "config/redis.json"
	// Default Logger configuration file
	defLoggerConfigurationFile string = "config/logger_admin.json"
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Default carver configuration file
	defCarverConfigurationFile string = "config/carver.json"
)

// Random
const (
	// Static files folder
	defStaticFilesFolder string = "./static"
	// Default templates folder
	defTemplatesFolder string = "./tmpl_admin"
	// Default carved files folder
	defCarvedFolder string = "./carved_files/"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default interval in seconds to expire queries/carves
	defaultExpiration int = 900
	// Default hours to classify nodes as inactive
	defaultInactive int = -72
)

// osquery
const (
	// osquery version to display tables
	defOsqueryTablesVersion = version.OsqueryVersion
	// JSON file with osquery tables data
	defOsqueryTablesFile string = "data/" + defOsqueryTablesVersion + ".json"
)

// Global general variables
var (
	err               error
	adminConfigValues types.JSONConfigurationAdmin
	adminConfig       types.JSONConfigurationAdmin
	s3LogConfig       types.S3Configuration
	s3CarverConfig    types.S3Configuration
	dbConfigValues    backend.JSONConfigurationDB
	dbConfig          backend.JSONConfigurationDB
	redisConfigValues cache.JSONConfigurationRedis
	redisConfig       cache.JSONConfigurationRedis
	db                *backend.DBManager
	redis             *cache.RedisManager
	settingsmgr       *settings.Settings
	nodesmgr          *nodes.NodeManager
	queriesmgr        *queries.Queries
	carvesmgr         *carves.Carves
	sessionsmgr       *sessions.SessionManager
	envs              *environments.Environment
	adminUsers        *users.UserManager
	tagsmgr           *tags.TagManager
	carvers3          *carves.CarverS3
	app               *cli.App
	flags             []cli.Flag
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []types.OsqueryTable
	adminMetrics  *metrics.Metrics
	handlersAdmin *handlers.HandlersAdmin
)

// Variables for flags
var (
	configFlag           bool
	dbFlag               bool
	redisFlag            bool
	serviceConfigFile    string
	dbConfigFile         string
	redisConfigFile      string
	tlsServer            bool
	tlsCertFile          string
	tlsKeyFile           string
	samlConfigFile       string
	jwtFlag              bool
	jwtConfigFile        string
	osqueryTablesFile    string
	osqueryTablesVersion string
	loggerFile           string
	loggerDbSame         bool
	staticFilesFolder    string
	staticOffline        bool
	carvedFilesFolder    string
	templatesFolder      string
	carverConfigFile     string
)

// SAML variables
var (
	samlMiddleware *samlsp.Middleware
	samlConfig     JSONConfigurationSAML
	samlData       samlThings
)

// JWT variables
var (
	jwtConfigValues types.JSONConfigurationJWT
	jwtConfig       types.JSONConfigurationJWT
)

// Valid values for auth in configuration
var validAuth = map[string]bool{
	settings.AuthDB:   true,
	settings.AuthSAML: true,
	settings.AuthJSON: true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	settings.CarverDB:    true,
	settings.CarverLocal: true,
	settings.CarverS3:    true,
}

// Function to load the configuration file
func loadConfiguration(file, service string) (types.JSONConfigurationAdmin, error) {
	var cfg types.JSONConfigurationAdmin
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Admin values
	adminRaw := viper.Sub(service)
	if adminRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", service, file)
	}
	if err := adminRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	if !validCarver[cfg.Carver] {
		return cfg, fmt.Errorf("Invalid carver method")
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
			Destination: &adminConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9001",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &adminConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthDB,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &adminConfigValues.Auth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &adminConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "session-key",
			Value:       "",
			Usage:       "Session key to generate cookies from it",
			EnvVars:     []string{"SESSION_KEY"},
			Destination: &adminConfigValues.SessionKey,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingDB,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &adminConfigValues.Logger,
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
			Name:        "redis-status-exp",
			Value:       cache.StatusExpiration,
			Usage:       "Redis expiration in hours for status logs",
			EnvVars:     []string{"REDIS_STATUS_EXP"},
			Destination: &redisConfigValues.StatusExpirationHours,
		},
		&cli.IntFlag{
			Name:        "redis-result-exp",
			Value:       cache.ResultExpiration,
			Usage:       "Redis expiration in hours for result logs",
			EnvVars:     []string{"REDIS_RESULT_EXP"},
			Destination: &redisConfigValues.ResultExpirationHours,
		},
		&cli.IntFlag{
			Name:        "redis-query-exp",
			Value:       cache.QueryExpiration,
			Usage:       "Redis expiration in hours for query logs",
			EnvVars:     []string{"REDIS_QUERY_EXP"},
			Destination: &redisConfigValues.QueryExpirationHours,
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
		&cli.StringFlag{
			Name:        "saml-file",
			Value:       defSAMLConfigurationFile,
			Usage:       "Load SAML configuration from `FILE`",
			EnvVars:     []string{"SAML_CONFIG_FILE"},
			Destination: &samlConfigFile,
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
		&cli.StringFlag{
			Name:        "osquery-version",
			Value:       defOsqueryTablesVersion,
			Usage:       "Set osquery version as default to be used",
			EnvVars:     []string{"OSQUERY_VERSION"},
			Destination: &osqueryTablesVersion,
		},
		&cli.StringFlag{
			Name:        "osquery-tables",
			Value:       defOsqueryTablesFile,
			Usage:       "Load osquery tables schema from `FILE`",
			EnvVars:     []string{"OSQUERY_TABLES"},
			Destination: &osqueryTablesFile,
		},
		&cli.StringFlag{
			Name:        "logger-file",
			Aliases:     []string{"F"},
			Value:       defLoggerConfigurationFile,
			Usage:       "Logger configuration to handle status/results logs from nodes",
			EnvVars:     []string{"LOGGER_FILE"},
			Destination: &loggerFile,
		},
		&cli.BoolFlag{
			Name:        "logger-db-same",
			Value:       false,
			Usage:       "Use the same DB configuration for the logger",
			EnvVars:     []string{"LOGGER_DB_SAME"},
			Destination: &loggerDbSame,
		},
		&cli.StringFlag{
			Name:        "static",
			Aliases:     []string{"s"},
			Value:       defStaticFilesFolder,
			Usage:       "Directory with all the static files needed for the osctrl-admin UI",
			EnvVars:     []string{"STATIC_FILES"},
			Destination: &staticFilesFolder,
		},
		&cli.BoolFlag{
			Name:        "static-offline",
			Aliases:     []string{"S"},
			Value:       false,
			Usage:       "Use offline static files (js and css). Default is online files.",
			EnvVars:     []string{"STATIC_ONLINE"},
			Destination: &staticOffline,
		},
		&cli.StringFlag{
			Name:        "templates",
			Value:       defTemplatesFolder,
			Usage:       "Directory with all the templates needed for the osctrl-admin UI",
			EnvVars:     []string{"STATIC_FILES"},
			Destination: &templatesFolder,
		},
		&cli.StringFlag{
			Name:        "carved",
			Value:       defCarvedFolder,
			Usage:       "Directory for all the received carved files from osquery",
			EnvVars:     []string{"CARVED_FILES"},
			Destination: &carvedFilesFolder,
		},
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       settings.CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_TYPE"},
			Destination: &adminConfig.Carver,
		},
		&cli.StringFlag{
			Name:        "carver-file",
			Value:       defCarverConfigurationFile,
			Usage:       "Carver configuration file to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_FILE"},
			Destination: &carverConfigFile,
		},
		&cli.StringFlag{
			Name:        "log-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_BUCKET"},
			Destination: &s3LogConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "log-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_REGION"},
			Destination: &s3LogConfig.Region,
		},
		&cli.StringFlag{
			Name:        "log-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_KEY_ID"},
			Destination: &s3LogConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "log-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_SECRET"},
			Destination: &s3LogConfig.SecretAccessKey,
		},
		&cli.StringFlag{
			Name:        "carver-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_BUCKET"},
			Destination: &s3CarverConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "carver-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_REGION"},
			Destination: &s3CarverConfig.Region,
		},
		&cli.StringFlag{
			Name:        "carve-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_KEY_ID"},
			Destination: &s3CarverConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "carve-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_SECRET"},
			Destination: &s3CarverConfig.SecretAccessKey,
		},
	}
	// Initialize zerolog logger with our custom parameters
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "2006-01-02T15:04:05.999Z07:00"}).With().Caller().Logger()
}

// Go go!
func osctrlAdminService() {
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
		log.Debug().Msgf("Backend NOT ready! Retrying in %d seconds...\n", dbConfig.ConnRetry)
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
		log.Debug().Msgf("Cache NOT ready! Retrying in %d seconds...\n", redisConfig.ConnRetry)
		time.Sleep(time.Duration(redisConfig.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize users")
	adminUsers = users.CreateUserManager(db.Conn, &jwtConfig)
	log.Info().Msg("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Info().Msg("Initialize environments")
	envs = environments.CreateEnvironment(db.Conn)
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Info().Msg("Initialize carves")
	carvesmgr = carves.CreateFileCarves(db.Conn, adminConfig.Carver, carvers3)
	log.Info().Msg("Initialize sessions")
	sessionsmgr = sessions.CreateSessionManager(db.Conn, authCookieName, adminConfig.SessionKey)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
	log.Info().Msg("Loading service metrics")
	adminMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading metrics - %v", err)
	}

	// Start SAML Middleware if we are using SAML
	if adminConfig.Auth == settings.AuthSAML {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Debug().Msg("DebugService: SAML keypair")
		}
		// Initialize SAML keypair to sign SAML Request.
		var err error
		samlData, err = keypairSAML(samlConfig)
		if err != nil {
			log.Fatal().Msgf("Can not initialize SAML keypair %s", err)
		}
		samlMiddleware, err = samlsp.New(samlsp.Options{
			URL:               *samlData.RootURL,
			Key:               samlData.KeyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       samlData.KeyPair.Leaf,
			IDPMetadata:       samlData.IdpMetadata,
			AllowIDPInitiated: true,
		})
		if err != nil {
			log.Fatal().Msgf("Can not initialize SAML Middleware %s", err)
		}
	}

	// FIXME Redis cache - Ticker to cleanup sessions
	// FIXME splay this?
	log.Info().Msg("Initialize cleanup sessions")
	go func() {
		_t := settingsmgr.CleanupSessions()
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Debug().Msg("DebugService: Cleaning up sessions")
			}
			sessionsmgr.Cleanup()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// Goroutine to cleanup expired queries and carves
	log.Info().Msg("Initialize cleanup queries/carves")
	go func() {
		_t := settingsmgr.CleanupExpired()
		if _t == 0 {
			_t = int64(defaultExpiration)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Debug().Msg("DebugService: Cleaning up expired queries/carves")
			}
			allEnvs, err := envs.All()
			if err != nil {
				log.Err(err).Msg("Error getting all environments")
			}
			for _, e := range allEnvs {
				// try to complete the queries first
				if err := queriesmgr.CleanupCompletedQueries(e.ID); err != nil {
					log.Err(err).Msg("Error completing expired queries")
				}
				if err := queriesmgr.CleanupExpiredQueries(e.ID); err != nil {
					log.Err(err).Msg("Error cleaning up expired queries")
				}
				if err := queriesmgr.CleanupExpiredCarves(e.ID); err != nil {
					log.Err(err).Msg("Error cleaning up expired carves")
				}
			}
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	var loggerDBConfig *backend.JSONConfigurationDB
	// Set the logger configuration file if we have a DB logger
	if adminConfig.Logger == settings.LoggingDB {
		if loggerDbSame {
			loggerFile = ""
			loggerDBConfig = &dbConfig
		}
	}

	// Initialize Admin handlers before router
	log.Info().Msg("Initializing handlers")
	handlersAdmin = handlers.CreateHandlersAdmin(
		handlers.WithDB(db.Conn),
		handlers.WithEnvs(envs),
		handlers.WithUsers(adminUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(carvesmgr),
		handlers.WithSettings(settingsmgr),
		handlers.WithMetrics(adminMetrics),
		handlers.WithCache(redis),
		handlers.WithSessions(sessionsmgr),
		handlers.WithVersion(serviceVersion),
		handlers.WithOsqueryVersion(osqueryTablesVersion),
		handlers.WithTemplates(templatesFolder),
		handlers.WithStaticLocation(staticOffline),
		handlers.WithOsqueryTables(osqueryTables),
		handlers.WithCarvesFolder(carvedFilesFolder),
		handlers.WithAdminConfig(&adminConfig),
		handlers.WithDBLogger(loggerFile, loggerDBConfig),
	)

	// ////////////////////////// ADMIN
	log.Info().Msg("Initializing router")
	// Create router for admin
	adminMux := http.NewServeMux()

	// ///////////////////////// UNAUTHENTICATED CONTENT
	// Admin: login only if local auth is enabled
	if adminConfig.Auth != settings.AuthNone && adminConfig.Auth != settings.AuthSAML {
		// login
		adminMux.HandleFunc("GET "+loginPath, handlersAdmin.LoginHandler)
		adminMux.HandleFunc("POST "+loginPath, handlersAdmin.LoginPOSTHandler)
		adminMux.HandleFunc("GET "+logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loginPath, http.StatusFound)
		})
	}
	// Admin: health of service
	adminMux.HandleFunc("GET "+healthPath, handlersAdmin.HealthHandler)
	// Admin: error
	adminMux.HandleFunc("GET "+errorPath, handlersAdmin.ErrorHandler)
	// Admin: forbidden
	adminMux.HandleFunc("GET "+forbiddenPath, handlersAdmin.ForbiddenHandler)
	// Admin: favicon
	adminMux.HandleFunc("GET "+faviconPath, handlersAdmin.FaviconHandler)
	// Admin: static
	adminMux.Handle("GET /static/", http.StripPrefix("/static", http.FileServer(http.Dir(staticFilesFolder))))

	// ///////////////////////// AUTHENTICATED CONTENT
	// Admin: JSON data for environments
	adminMux.Handle("GET /json/environment/{env}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONEnvironmentHandler)))
	// Admin: JSON data for platforms
	adminMux.Handle("GET /json/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONPlatformHandler)))
	// Admin: JSON data for logs
	adminMux.Handle("GET /json/logs/{type}/{env}/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONLogsHandler)))
	// Admin: JSON data for query logs
	adminMux.Handle("GET /json/query/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryLogsHandler)))
	// Admin: JSON data for sidebar stats
	adminMux.Handle("GET /json/stats/{target}/{identifier}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONStatsHandler)))
	// Admin: JSON data for tags
	adminMux.Handle("GET /json/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONTagsHandler)))
	// Admin: table for environments
	adminMux.Handle("GET /environment/{env}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvironmentHandler)))
	// Admin: table for platforms
	adminMux.Handle("GET /platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PlatformHandler)))
	// Admin: root
	adminMux.Handle("GET /", handlerAuthCheck(http.HandlerFunc(handlersAdmin.RootHandler)))
	// Admin: node view
	adminMux.Handle("GET /node/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeHandler)))
	// Admin: multi node action
	adminMux.Handle("POST /node/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeActionsPOSTHandler)))
	// Admin: run queries
	adminMux.Handle("GET /query/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunGETHandler)))
	adminMux.Handle("POST /query/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunPOSTHandler)))
	// Admin: list queries
	adminMux.Handle("GET /query/{env}/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryListGETHandler)))
	// Admin: saved queries
	adminMux.Handle("GET /query/{env}/saved", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SavedQueriesGETHandler)))
	// Admin: query actions
	adminMux.Handle("POST /query/{env}/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryActionsPOSTHandler)))
	// Admin: query JSON
	adminMux.Handle("GET /query/{env}/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryHandler)))
	// Admin: query logs
	adminMux.Handle("GET /query/{env}/logs/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryLogsHandler)))
	// Admin: carve files
	adminMux.Handle("GET /carves/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunGETHandler)))
	adminMux.Handle("POST /carves/{env}/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunPOSTHandler)))
	// Admin: list carves
	adminMux.Handle("GET /carves/{env}/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesListGETHandler)))
	// Admin: carves actions
	adminMux.Handle("POST /carves/{env}/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesActionsPOSTHandler)))
	// Admin: carves JSON
	adminMux.Handle("GET /carves/{env}/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONCarvesHandler)))
	// Admin: carves details
	adminMux.Handle("GET /carves/{env}/details/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDetailsHandler)))
	// Admin: carves download
	adminMux.Handle("GET /carves/{env}/download/{sessionid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDownloadHandler)))
	// Admin: nodes configuration
	adminMux.Handle("GET /conf/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfGETHandler)))
	adminMux.Handle("POST /conf/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfPOSTHandler)))
	adminMux.Handle("POST /intervals/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.IntervalsPOSTHandler)))
	// Admin: nodes enroll
	adminMux.Handle("GET /enroll/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollGETHandler)))
	adminMux.Handle("POST /enroll/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollPOSTHandler)))
	adminMux.Handle("GET /enroll/{env}/download/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollDownloadHandler)))
	adminMux.Handle("POST /expiration/{env}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ExpirationPOSTHandler)))
	// Admin: server settings
	adminMux.Handle("GET /settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsGETHandler)))
	adminMux.Handle("POST /settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsPOSTHandler)))
	// Admin: manage environments
	adminMux.Handle("GET /environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsGETHandler)))
	adminMux.Handle("POST /environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsPOSTHandler)))
	// Admin: manage users
	adminMux.Handle("GET /users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersGETHandler)))
	adminMux.Handle("POST /users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersPOSTHandler)))
	adminMux.Handle("GET /users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsGETHandler)))
	adminMux.Handle("POST /users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsPOSTHandler)))
	// Admin: manage tags
	adminMux.Handle("GET /tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsGETHandler)))
	adminMux.Handle("POST /tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsPOSTHandler)))
	adminMux.Handle("POST /tags/nodes", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagNodesPOSTHandler)))
	// Admin: manage tokens
	adminMux.Handle("GET /tokens/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensGETHandler)))
	adminMux.Handle("POST /tokens/{username}/refresh", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensPOSTHandler)))
	// Admin: edit profile
	adminMux.Handle("GET /profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfileGETHandler)))
	adminMux.Handle("POST /profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfilePOSTHandler)))
	// Admin: dashboard and search bar
	adminMux.Handle("GET /dashboard", handlerAuthCheck(http.HandlerFunc(handlersAdmin.DashboardGETHandler)))
	// Admin: logout
	adminMux.Handle("POST "+logoutPath, handlerAuthCheck(http.HandlerFunc(handlersAdmin.LogoutPOSTHandler)))
	// SAML ACS
	if adminConfig.Auth == settings.AuthSAML {
		adminMux.Handle("GET /saml/", samlMiddleware)
		adminMux.HandleFunc("GET "+loginPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
		})
		adminMux.HandleFunc("GET "+logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LogoutURL, http.StatusFound)
		})
	}
	// Launch HTTP server for admin
	serviceListener := adminConfig.Listener + ":" + adminConfig.Port
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
			Handler:      adminMux,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		if err := http.ListenAndServe(serviceListener, adminMux); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if configFlag {
		adminConfig, err = loadConfiguration(serviceConfigFile, settings.ServiceAdmin)
		if err != nil {
			return fmt.Errorf("Failed to load service configuration %s - %s", serviceConfigFile, err)
		}
	} else {
		adminConfig = adminConfigValues
	}
	// Load redis configuration if external JSON config file is used
	if redisFlag {
		redisConfig, err = cache.LoadConfiguration(redisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("Failed to load redis configuration - %v", err)
		}
	} else {
		redisConfig = redisConfigValues
	}
	// Load DB configuration if external JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
		}
	} else {
		dbConfig = dbConfigValues
	}
	// Load SAML configuration if this authentication is used in the service config
	if adminConfig.Auth == settings.AuthSAML {
		samlConfig, err = loadSAML(samlConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load SAML configuration - %v", err)
		}
	}
	// Load JWT configuration if external JWT JSON config file is used
	if jwtFlag {
		jwtConfig, err = loadJWTConfiguration(jwtConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load JWT configuration - %v", err)
		}
	} else {
		jwtConfig = jwtConfigValues
	}
	// Load osquery tables JSON file
	osqueryTables, err = loadOsqueryTables(osqueryTablesFile)
	if err != nil {
		return fmt.Errorf("Failed to load osquery tables - %v", err)
	}
	// Load carver configuration if external JSON config file is used
	if adminConfig.Carver == settings.CarverS3 {
		if s3CarverConfig.Bucket != "" {
			carvers3, err = carves.CreateCarverS3(s3CarverConfig)
		} else {
			carvers3, err = carves.CreateCarverS3File(carverConfigFile)
		}
		if err != nil {
			return fmt.Errorf("Failed to initiate s3 carver - %v", err)
		}
	}
	return nil
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
		log.Fatal().Msgf("app.Run error: %v", err)
	}
	// Service starts!
	osctrlAdminService()
}
