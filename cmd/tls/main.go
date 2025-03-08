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

	"github.com/jmpsec/osctrl/cmd/tls/handlers"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceTLS
	// Service version
	serviceVersion string = version.OsctrlVersion
	// Service description
	serviceDescription string = "TLS service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Default service configuration file
	defConfigurationFile string = "config/" + settings.ServiceTLS + ".json"
	// Default DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile string = "config/redis.json"
	// Default Logger configuration file
	defLoggerConfigurationFile string = "config/logger_tls.json"
	// Default carver configuration file
	defCarverConfigurationFile string = "config/carver_tls.json"
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default accelerate interval in seconds
	defaultAccelerate int = 60
	// Default expiration of oneliners for enroll/expire
	defaultOnelinerExpiration bool = true
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// Global variables
var (
	err                error
	tlsConfigValues    types.JSONConfigurationTLS
	tlsConfig          types.JSONConfigurationTLS
	dbConfigValues     backend.JSONConfigurationDB
	dbConfig           backend.JSONConfigurationDB
	redisConfigValues  cache.JSONConfigurationRedis
	redisConfig        cache.JSONConfigurationRedis
	db                 *backend.DBManager
	redis              *cache.RedisManager
	settingsmgr        *settings.Settings
	envs               *environments.Environment
	envsmap            environments.MapEnvironments
	settingsmap        settings.MapSettings
	nodesmgr           *nodes.NodeManager
	queriesmgr         *queries.Queries
	filecarves         *carves.Carves
	tlsMetrics         *metrics.Metrics
	loggerTLS          *logging.LoggerTLS
	handlersTLS        *handlers.HandlersTLS
	tagsmgr            *tags.TagManager
	carvers3           *carves.CarverS3
	s3LogConfig        types.S3Configuration
	s3CarverConfig     types.S3Configuration
	kafkaConfiguration types.KafkaConfiguration
	app                *cli.App
	flags              []cli.Flag
)

// Variables for flags
var (
	configFlag        bool
	serviceConfigFile string
	redisConfigFile   string
	dbFlag            bool
	redisFlag         bool
	dbConfigFile      string
	tlsServer         bool
	tlsCertFile       string
	tlsKeyFile        string
	loggerFlag        bool
	loggerFile        string
	loggerDbSame      bool
	alwaysLog         bool
	carverConfigFile  string
)

// Valid values for authentication in configuration
var validAuth = map[string]bool{
	settings.AuthNone: true,
}

// Valid values for logging in configuration
var validLogging = map[string]bool{
	settings.LoggingNone:     true,
	settings.LoggingStdout:   true,
	settings.LoggingFile:     true,
	settings.LoggingDB:       true,
	settings.LoggingGraylog:  true,
	settings.LoggingSplunk:   true,
	settings.LoggingLogstash: true,
	settings.LoggingKinesis:  true,
	settings.LoggingS3:       true,
	settings.LoggingElastic:  true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	settings.CarverDB:    true,
	settings.CarverLocal: true,
	settings.CarverS3:    true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file, service string) (types.JSONConfigurationTLS, error) {
	var cfg types.JSONConfigurationTLS
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// TLS endpoint values
	tlsRaw := viper.Sub(service)
	if tlsRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", service, file)
	}
	if err := tlsRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	if !validLogging[cfg.Logger] {
		return cfg, fmt.Errorf("Invalid logging method")
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
			Destination: &tlsConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9000",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &tlsConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "log-level",
			Value:       types.LogLevelInfo,
			Usage:       "Log level for the service",
			EnvVars:     []string{"SERVICE_LOG_LEVEL"},
			Destination: &tlsConfigValues.LogLevel,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Value:       types.LogFormatJSON,
			Usage:       "Log format for the service",
			EnvVars:     []string{"SERVICE_LOG_FORMAT"},
			Destination: &tlsConfigValues.LogFormat,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &tlsConfigValues.Auth,
		},
		&cli.StringFlag{
			Name:        "metrics-listener",
			Value:       "0.0.0.0",
			Usage:       "Listener for prometheus metrics",
			EnvVars:     []string{"METRICS_LISTENER"},
			Destination: &tlsConfigValues.MetricsListener,
		},
		&cli.StringFlag{
			Name:        "metrics-port",
			Value:       "9090",
			Usage:       "Port for exposing prometheus metrics",
			EnvVars:     []string{"METRICS_PORT"},
			Destination: &tlsConfigValues.MetricsPort,
		},
		&cli.BoolFlag{
			Name:        "metrics-enabled",
			Value:       false,
			Usage:       "Enable prometheus metrics",
			EnvVars:     []string{"METRICS_ENABLED"},
			Destination: &tlsConfigValues.MetricsEnabled,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &tlsConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "logger",
			Aliases:     []string{"L"},
			Value:       settings.LoggingDB,
			Usage:       "Logger mechanism to handle status/result logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &tlsConfigValues.Logger,
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
		&cli.BoolFlag{
			Name:        "always-log",
			Aliases:     []string{"a", "always"},
			Value:       false,
			Usage:       "Always log status and on-demand query logs from nodes in database",
			EnvVars:     []string{"ALWAYS_LOG"},
			Destination: &alwaysLog,
		},
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       settings.CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_TYPE"},
			Destination: &tlsConfig.Carver,
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
		&cli.StringFlag{
			Name:        "log-kafka-boostrap-servers",
			Value:       "",
			Usage:       "Kafka bootstrap servers to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_BOOTSTRAP_SERVERS"},
			Destination: &kafkaConfiguration.BoostrapServer,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sslca-location",
			Value:       "",
			Usage:       "Kafka sslca location to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SSLCA_LOCATION"},
			Destination: &kafkaConfiguration.SSLCALocation,
		},
		&cli.DurationFlag{
			Name:        "log-kafka-connection-timeout",
			Value:       5 * time.Second,
			Usage:       "Kafka connection timeout to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_CONNECTION_TIMEOUT"},
			Destination: &kafkaConfiguration.ConnectionTimeout,
		},
		&cli.StringFlag{
			Name:        "log-kafka-topic",
			Value:       "",
			Usage:       "Kafka topic to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_TOPIC"},
			Destination: &kafkaConfiguration.Topic,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-mechanism",
			Value:       "",
			Usage:       "Kafka sasl mechanism' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_MECHANISM"},
			Destination: &kafkaConfiguration.SASL.Mechanism,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-username",
			Value:       "",
			Usage:       "Kafka sasl username' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_USERNAME"},
			Destination: &kafkaConfiguration.SASL.Username,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-password",
			Value:       "",
			Usage:       "Kafka sasl password' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_PASSWORD"},
			Destination: &kafkaConfiguration.SASL.Password,
		},
	}

}

// Go go!
func osctrlService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	// Attempt to connect to backend waiting until is ready
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
	// Attempt to connect to cache waiting until is ready
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
	log.Info().Msg("Initialize environment")
	envs = environments.CreateEnvironment(db.Conn)
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn, redis.Client)
	log.Info().Msg("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Info().Msg("Initialize carves")
	filecarves = carves.CreateFileCarves(db.Conn, tlsConfig.Carver, carvers3)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatal().Msgf("Error loading settings - %s: %v", tlsConfig.Logger, err)
	}
	// Initialize service metrics
	log.Info().Msg("Loading service metrics")
	tlsMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading metrics - %v", err)
	}

	// Initialize TLS logger
	log.Info().Msg("Loading TLS logger")
	loggerTLS, err = logging.CreateLoggerTLS(
		tlsConfig.Logger, loggerFile, s3LogConfig, kafkaConfiguration, loggerDbSame, alwaysLog, dbConfig, settingsmgr, nodesmgr, queriesmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading logger - %s: %v", tlsConfig.Logger, err)
	}
	// Sleep to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Info().Msg("Preparing pseudo-cache for environments")
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceTLS) {
				log.Info().Msg("DebugService: Refreshing environments")
			}
			envsmap = refreshEnvironments()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	// Sleep to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Info().Msg("Preparing pseudo-cache for settings")
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceTLS) {
				log.Info().Msg("DebugService: Refreshing settings")
			}
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	if tlsConfig.MetricsEnabled {
		log.Info().Msg("Metrics are enabled")
		// Register Prometheus metrics
		handlers.RegisterMetrics(prometheus.DefaultRegisterer)

		// Creating a new prometheus service
		prometheusServer := http.NewServeMux()
		prometheusServer.Handle("/metrics", promhttp.Handler())

		go func() {
			log.Info().Msgf("Starting prometheus server at %s:%s", tlsConfig.MetricsListener, tlsConfig.MetricsPort)
			err := http.ListenAndServe(tlsConfig.MetricsListener+":"+tlsConfig.MetricsPort, prometheusServer)
			if err != nil {
				log.Fatal().Msgf("Error starting prometheus server: %v", err)
			}
		}()
	}
	// Initialize TLS handlers before router
	log.Info().Msg("Initializing handlers")
	handlersTLS = handlers.CreateHandlersTLS(
		handlers.WithEnvs(envs),
		handlers.WithEnvsMap(&envsmap),
		handlers.WithNodes(nodesmgr),
		handlers.WithTags(tagsmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(filecarves),
		handlers.WithSettings(settingsmgr),
		handlers.WithSettingsMap(&settingsmap),
		handlers.WithMetrics(tlsMetrics),
		handlers.WithLogs(loggerTLS),
	)

	// ///////////////////////// ALL CONTENT IS UNAUTHENTICATED FOR TLS
	log.Info().Msg("Initializing router")
	// Create router for TLS endpoint
	muxTLS := http.NewServeMux()
	// TLS: root
	muxTLS.HandleFunc("GET /", handlersTLS.RootHandler)
	// TLS: testing
	muxTLS.HandleFunc("GET "+healthPath, handlersTLS.HealthHandler)
	// TLS: error
	muxTLS.HandleFunc("GET "+errorPath, handlersTLS.ErrorHandler)
	// TLS: Specific routes for osquery nodes
	// FIXME this forces all paths to be the same

	muxTLS.Handle("POST /{env}/"+environments.DefaultEnrollPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.EnrollHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultConfigPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.ConfigHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultLogPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.LogHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultQueryReadPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.QueryReadHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultQueryWritePath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.QueryWriteHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultCarverInitPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.CarveInitHandler)))
	muxTLS.Handle("POST /{env}/"+environments.DefaultCarverBlockPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.CarveBlockHandler)))
	// TLS: Quick enroll/remove script
	muxTLS.HandleFunc("GET /{env}/{secretpath}/{script}", handlersTLS.QuickEnrollHandler)
	// TLS: Download enrolling package
	muxTLS.HandleFunc("GET /{env}/{secretpath}/package/{package}", handlersTLS.EnrollPackageHandler)
	// TLS: osctrld retrieve flags
	muxTLS.HandleFunc("POST /{env}/"+environments.DefaultFlagsPath, handlersTLS.FlagsHandler)
	// TLS: osctrld retrieve certificate
	muxTLS.HandleFunc("POST /{env}/"+environments.DefaultCertPath, handlersTLS.CertHandler)
	// TLS: osctrld verification
	muxTLS.HandleFunc("POST /{env}/"+environments.DefaultVerifyPath, handlersTLS.VerifyHandler)
	// TLS: osctrld retrieve script to install/remove osquery
	muxTLS.HandleFunc("POST /{env}/{action}/{platform}/"+environments.DefaultScriptPath, handlersTLS.ScriptHandler)

	// ////////////////////////////// Everything is ready at this point!
	serviceListener := tlsConfig.Listener + ":" + tlsConfig.Port
	if tlsServer {
		log.Info().Msg("TLS Termination is enabled")
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
			Handler:      muxTLS,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		if err := http.ListenAndServe(serviceListener, muxTLS); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if configFlag {
		tlsConfig, err = loadConfiguration(serviceConfigFile, settings.ServiceTLS)
		if err != nil {
			return fmt.Errorf("Error loading %s - %s", serviceConfigFile, err)
		}
	} else {
		tlsConfig = tlsConfigValues
	}
	// Load db configuration if external JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
		}
	} else {
		dbConfig = dbConfigValues
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
	// Load carver configuration if external JSON config file is used
	if tlsConfig.Carver == settings.CarverS3 {
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
	initializeLogger(tlsConfig.LogLevel, tlsConfig.LogFormat)
	// Service starts!
	osctrlService()
}
