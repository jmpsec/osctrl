package config

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/urfave/cli/v3"
)

// Default values
const (
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 10
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 10
)

// osquery
const (
	// osquery version to display tables
	defOsqueryTablesVersion = version.OsqueryVersion
	// JSON file with osquery tables data
	defOsqueryTablesFile string = "data/" + defOsqueryTablesVersion + ".json"
	// Default SAML configuration file
	defSAMLConfigurationFile string = "config/saml.json"
	// Default JWT configuration file
	defJWTConfigurationFile string = "config/jwt.json"
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Static files folder
	defStaticFilesFolder string = "./static"
	// Default templates folder
	defTemplatesFolder string = "./tmpl_admin"
	// Default carved files folder
	defCarvedFolder string = "./carved_files/"
	// Default background image file
	defBackgroundImageFile string = defStaticFilesFolder + "/img/circuit.svg"
	// Default branding image file
	defBrandingImageFile string = defStaticFilesFolder + "/img/brand.png"
	// Default DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile string = "config/redis.json"
	// Default db filepath for sqlite
	defSQLiteDBFile string = "./osctrl.db"
)

// ServiceFlagParams stores flag values for the each service
type ServiceFlagParams struct {
	// Configuration will be loaded from a file
	ConfigFlag bool
	// Service configuration file
	ServiceConfigFile string
	// DB configuration will be loaded from a file
	DBFlag bool
	// DB configuration file
	DBConfigFile string
	// Redis configuration will be loaded from a file
	RedisFlag bool
	// Redis configuration file
	RedisConfigFile string

	// Enable TLS termination
	TLSServer bool
	// TLS certificate file
	TLSCertFile string
	// TLS private key file
	TLSKeyFile string

	// Logger configuration file
	LoggerFile string
	// Logger DB configuration will be the same as the main DB
	LoggerDBSame bool
	// Always log status and on-demand query logs from nodes in database
	AlwaysLog bool

	// Carver configuration file
	CarverConfigFile string

	// JWT configuration will be loaded from a file
	JWTFlag bool
	// JWT configuration file
	JWTConfigFile string

	// osquery configuration values
	OsqueryConfigValues OsqueryConfiguration

	// SAML configuration file
	SAMLConfigFile string
	// Static files folder
	StaticFiles string
	// Use offline static files
	StaticOffline bool
	// Templates folder
	TemplatesDir string
	// Carved files folder
	CarvedDir string
	// Branding image file
	BrandingImage string
	// Background image file
	BackgroundImage string
	// Audit log
	AuditLog bool

	// Debug HTTP configuration values
	DebugHTTPValues DebugHTTPConfiguration

	// osctrld configuration values
	OsctrldConfigValues OsctrldConfiguration

	// Service configuration values
	ConfigValues JSONConfigurationService
	// DB writer configuration values
	WriterConfig JSONConfigurationWriter
	// DB configuration values
	DBConfigValues backend.JSONConfigurationDB
	// Redis configuration values
	RedisConfigValues cache.JSONConfigurationRedis
	// S3 loggging configuration values
	S3LogConfig S3Configuration
	// S3 carver configuration values
	S3CarverConfig S3Configuration
	// Kafka logging configuration values
	KafkaConfiguration KafkaConfiguration
	// JWT configuration values
	JWTConfigValues JSONConfigurationJWT
}

// InitTLSFlags initializes all the flags needed for the TLS service
func InitTLSFlags(params *ServiceFlagParams) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, initServiceFlags(params)...)
	allFlags = append(allFlags, initLoggingFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, initMetricsFlags(params)...)
	allFlags = append(allFlags, initWriterFlags(params)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initOsctrldFlags(params)...)
	allFlags = append(allFlags, initOsqueryFlags(params)...)
	allFlags = append(allFlags, initCarverFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, initS3LoggingFlags(params)...)
	allFlags = append(allFlags, initKafkaFlags(params)...)
	allFlags = append(allFlags, initDebugFlags(params, ServiceTLS)...)
	return allFlags
}

// InitAdminFlags initializes all the flags needed for the Admin service
func InitAdminFlags(params *ServiceFlagParams) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params, ServiceAdmin)...)
	allFlags = append(allFlags, initServiceFlags(params)...)
	allFlags = append(allFlags, initLoggingFlags(params, ServiceAdmin)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initOsctrldFlags(params)...)
	allFlags = append(allFlags, initCarverFlags(params, ServiceAdmin)...)
	allFlags = append(allFlags, initS3LoggingFlags(params)...)
	allFlags = append(allFlags, initJWTFlags(params)...)
	allFlags = append(allFlags, initOsqueryFlags(params)...)
	allFlags = append(allFlags, initAdminFlags(params)...)
	allFlags = append(allFlags, initDebugFlags(params, ServiceAdmin)...)
	return allFlags
}

// InitAPIFlags initializes all the flags needed for the API service
func InitAPIFlags(params *ServiceFlagParams) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params, ServiceAPI)...)
	allFlags = append(allFlags, initServiceFlags(params)...)
	allFlags = append(allFlags, initLoggingFlags(params, ServiceAPI)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initJWTFlags(params)...)
	allFlags = append(allFlags, initOsqueryFlags(params)...)
	allFlags = append(allFlags, initApiFlags(params)...)
	allFlags = append(allFlags, initDebugFlags(params, ServiceAPI)...)
	return allFlags
}

// initConfigFlags initializes configuration-related flags
func initConfigFlags(params *ServiceFlagParams, service string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via JSON file",
			Sources:     cli.EnvVars("SERVICE_CONFIG"),
			Destination: &params.ConfigFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       "config/" + service + ".json",
			Usage:       "Load service configuration from `FILE`",
			Sources:     cli.EnvVars("SERVICE_CONFIG_FILE"),
			Destination: &params.ServiceConfigFile,
		},
	}
}

// initServiceFlags initializes main service-related flags
func initServiceFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			Sources:     cli.EnvVars("SERVICE_LISTENER"),
			Destination: &params.ConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9000",
			Usage:       "TCP port for the service",
			Sources:     cli.EnvVars("SERVICE_PORT"),
			Destination: &params.ConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			Sources:     cli.EnvVars("SERVICE_HOST"),
			Destination: &params.ConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       AuthNone,
			Usage:       "Authentication mechanism for the service",
			Sources:     cli.EnvVars("SERVICE_AUTH"),
			Destination: &params.ConfigValues.Auth,
		},
		&cli.StringFlag{
			Name:        "log-level",
			Value:       LogLevelInfo,
			Usage:       "Log level for the service",
			Sources:     cli.EnvVars("SERVICE_LOG_LEVEL"),
			Destination: &params.ConfigValues.LogLevel,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Value:       LogFormatJSON,
			Usage:       "Log format for the service",
			Sources:     cli.EnvVars("SERVICE_LOG_FORMAT"),
			Destination: &params.ConfigValues.LogFormat,
		},
	}
}

// initLoggingFlags initializes logging-related flags
func initLoggingFlags(params *ServiceFlagParams, service string) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "logger",
			Aliases:     []string{"L"},
			Value:       LoggingDB,
			Usage:       "Logger mechanism to handle status/result logs from nodes",
			Sources:     cli.EnvVars("SERVICE_LOGGER"),
			Destination: &params.ConfigValues.Logger,
		},
		&cli.StringFlag{
			Name:        "logger-file",
			Aliases:     []string{"F"},
			Value:       "config/logger_" + service + ".json",
			Usage:       "Logger configuration to handle status/results logs from nodes",
			Sources:     cli.EnvVars("LOGGER_FILE"),
			Destination: &params.LoggerFile,
		},
		&cli.BoolFlag{
			Name:        "logger-db-same",
			Value:       false,
			Usage:       "Use the same DB configuration for the logger",
			Sources:     cli.EnvVars("LOGGER_DB_SAME"),
			Destination: &params.LoggerDBSame,
		},
		&cli.BoolFlag{
			Name:        "always-log",
			Aliases:     []string{"a", "always"},
			Value:       false,
			Usage:       "Always log status and on-demand query logs from nodes in database",
			Sources:     cli.EnvVars("ALWAYS_LOG"),
			Destination: &params.AlwaysLog,
		},
	}
}

// initMetricsFlags initializes metrics-related flags
func initMetricsFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "metrics-listener",
			Value:       "0.0.0.0",
			Usage:       "Listener for prometheus metrics",
			Sources:     cli.EnvVars("METRICS_LISTENER"),
			Destination: &params.ConfigValues.MetricsListener,
		},
		&cli.StringFlag{
			Name:        "metrics-port",
			Value:       "9090",
			Usage:       "Port for exposing prometheus metrics",
			Sources:     cli.EnvVars("METRICS_PORT"),
			Destination: &params.ConfigValues.MetricsPort,
		},
		&cli.BoolFlag{
			Name:        "metrics-enabled",
			Value:       false,
			Usage:       "Enable prometheus metrics",
			Sources:     cli.EnvVars("METRICS_ENABLED"),
			Destination: &params.ConfigValues.MetricsEnabled,
		},
	}
}

// initWriterFlags initializes writer-related flags
func initWriterFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "writer-batch-size",
			Value:       50,
			Usage:       "Maximum number of events before flushing",
			Sources:     cli.EnvVars("WRITER_BATCH_SIZE"),
			Destination: &params.WriterConfig.WriterBatchSize,
		},
		&cli.DurationFlag{
			Name:        "writer-timeout",
			Value:       60 * time.Second,
			Usage:       "Maximum wait time before flushing",
			Sources:     cli.EnvVars("WRITER_TIMEOUT"),
			Destination: &params.WriterConfig.WriterTimeout,
		},
		&cli.IntFlag{
			Name:        "writer-buffer-size",
			Value:       2000,
			Usage:       "Size of the event channel buffer",
			Sources:     cli.EnvVars("WRITER_BUFFER_SIZE"),
			Destination: &params.WriterConfig.WriterBufferSize,
		},
	}
}

// initRedisFlags initializes Redis-related flags
func initRedisFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "redis",
			Aliases:     []string{"r"},
			Value:       false,
			Usage:       "Provide redis configuration via JSON file",
			Sources:     cli.EnvVars("REDIS_CONFIG"),
			Destination: &params.RedisFlag,
		},
		&cli.StringFlag{
			Name:        "redis-file",
			Aliases:     []string{"R"},
			Value:       defRedisConfigurationFile,
			Usage:       "Load redis configuration from `FILE`",
			Sources:     cli.EnvVars("REDIS_CONFIG_FILE"),
			Destination: &params.RedisConfigFile,
		},
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			Sources:     cli.EnvVars("REDIS_CONNECTION_STRING"),
			Destination: &params.RedisConfigValues.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			Sources:     cli.EnvVars("REDIS_HOST"),
			Destination: &params.RedisConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "redis-port",
			Value:       "6379",
			Usage:       "Redis port to be connected to",
			Sources:     cli.EnvVars("REDIS_PORT"),
			Destination: &params.RedisConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			Sources:     cli.EnvVars("REDIS_PASS"),
			Destination: &params.RedisConfigValues.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			Sources:     cli.EnvVars("REDIS_DB"),
			Destination: &params.RedisConfigValues.DB,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			Sources:     cli.EnvVars("REDIS_CONN_RETRY"),
			Destination: &params.RedisConfigValues.ConnRetry,
		},
	}
}

// initDBFlags initializes database-related flags
func initDBFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			Sources:     cli.EnvVars("DB_CONFIG"),
			Destination: &params.DBFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			Sources:     cli.EnvVars("DB_CONFIG_FILE"),
			Destination: &params.DBConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-type",
			Value:       "postgres",
			Usage:       "Type of backend to be used",
			Sources:     cli.EnvVars("DB_TYPE"),
			Destination: &params.DBConfigValues.Type,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			Sources:     cli.EnvVars("DB_HOST"),
			Destination: &params.DBConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			Sources:     cli.EnvVars("DB_PORT"),
			Destination: &params.DBConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			Sources:     cli.EnvVars("DB_NAME"),
			Destination: &params.DBConfigValues.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			Sources:     cli.EnvVars("DB_USER"),
			Destination: &params.DBConfigValues.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			Sources:     cli.EnvVars("DB_PASS"),
			Destination: &params.DBConfigValues.Password,
		},
		&cli.StringFlag{
			Name:        "db-sslmode",
			Value:       "disable",
			Usage:       "SSL native support to encrypt the connection to the backend",
			Sources:     cli.EnvVars("DB_SSLMODE"),
			Destination: &params.DBConfigValues.SSLMode,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			Sources:     cli.EnvVars("DB_MAX_IDLE_CONNS"),
			Destination: &params.DBConfigValues.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			Sources:     cli.EnvVars("DB_MAX_OPEN_CONNS"),
			Destination: &params.DBConfigValues.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			Sources:     cli.EnvVars("DB_CONN_MAX_LIFETIME"),
			Destination: &params.DBConfigValues.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			Sources:     cli.EnvVars("DB_CONN_RETRY"),
			Destination: &params.DBConfigValues.ConnRetry,
		},
		&cli.StringFlag{
			Name:        "db-filepath",
			Value:       defSQLiteDBFile,
			Usage:       "File path to the SQLite database, only used when type is sqlite",
			Sources:     cli.EnvVars("DB_SQLITE_FILEPATH"),
			Destination: &params.DBConfigValues.FilePath,
		},
	}
}

// initTLSSecurityFlags initializes TLS security-related flags
func initTLSSecurityFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			Sources:     cli.EnvVars("TLS_SERVER"),
			Destination: &params.TLSServer,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       defTLSCertificateFile,
			Usage:       "TLS termination certificate from `FILE`",
			Sources:     cli.EnvVars("TLS_CERTIFICATE"),
			Destination: &params.TLSCertFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       defTLSKeyFile,
			Usage:       "TLS termination private key from `FILE`",
			Sources:     cli.EnvVars("TLS_KEY"),
			Destination: &params.TLSKeyFile,
		},
	}
}

// initCarverFlags initializes carver-related flags
func initCarverFlags(params *ServiceFlagParams, service string) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			Sources:     cli.EnvVars("CARVER_TYPE"),
			Destination: &params.ConfigValues.Carver,
		},
		&cli.StringFlag{
			Name:        "carver-file",
			Value:       "config/carver_" + service + ".json",
			Usage:       "Carver configuration file to receive files extracted from nodes",
			Sources:     cli.EnvVars("CARVER_FILE"),
			Destination: &params.CarverConfigFile,
		},
		&cli.StringFlag{
			Name:        "carver-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_BUCKET"),
			Destination: &params.S3CarverConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "carver-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_REGION"),
			Destination: &params.S3CarverConfig.Region,
		},
		&cli.StringFlag{
			Name:        "carve-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_KEY_ID"),
			Destination: &params.S3CarverConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "carve-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_SECRET"),
			Destination: &params.S3CarverConfig.SecretAccessKey,
		},
	}
}

// initS3LoggingFlags initializes S3 logging-related flags
func initS3LoggingFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_BUCKET"),
			Destination: &params.S3LogConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "log-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_REGION"),
			Destination: &params.S3LogConfig.Region,
		},
		&cli.StringFlag{
			Name:        "log-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_KEY_ID"),
			Destination: &params.S3LogConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "log-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_SECRET"),
			Destination: &params.S3LogConfig.SecretAccessKey,
		},
	}
}

// initKafkaFlags initializes Kafka-related flags
func initKafkaFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-kafka-boostrap-servers",
			Value:       "",
			Usage:       "Kafka bootstrap servers to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_BOOTSTRAP_SERVERS"),
			Destination: &params.KafkaConfiguration.BootstrapServer,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sslca-location",
			Value:       "",
			Usage:       "Kafka sslca location to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SSLCA_LOCATION"),
			Destination: &params.KafkaConfiguration.SSLCALocation,
		},
		&cli.DurationFlag{
			Name:        "log-kafka-connection-timeout",
			Value:       5 * time.Second,
			Usage:       "Kafka connection timeout to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_CONNECTION_TIMEOUT"),
			Destination: &params.KafkaConfiguration.ConnectionTimeout,
		},
		&cli.StringFlag{
			Name:        "log-kafka-topic",
			Value:       "",
			Usage:       "Kafka topic to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_TOPIC"),
			Destination: &params.KafkaConfiguration.Topic,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-mechanism",
			Value:       "",
			Usage:       "Kafka sasl mechanism' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_MECHANISM"),
			Destination: &params.KafkaConfiguration.SASL.Mechanism,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-username",
			Value:       "",
			Usage:       "Kafka sasl username' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_USERNAME"),
			Destination: &params.KafkaConfiguration.SASL.Username,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-password",
			Value:       "",
			Usage:       "Kafka sasl password' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_PASSWORD"),
			Destination: &params.KafkaConfiguration.SASL.Password,
		},
	}
}

// initJWTFlags initializes JWT flags
func initJWTFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "jwt",
			Aliases:     []string{"j"},
			Value:       false,
			Usage:       "Provide JWT configuration via JSON file",
			Sources:     cli.EnvVars("JWT_CONFIG"),
			Destination: &params.JWTFlag,
		},
		&cli.StringFlag{
			Name:        "jwt-file",
			Value:       defJWTConfigurationFile,
			Usage:       "Load JWT configuration from `FILE`",
			Sources:     cli.EnvVars("JWT_CONFIG_FILE"),
			Destination: &params.JWTConfigFile,
		},
		&cli.StringFlag{
			Name:        "jwt-secret",
			Usage:       "Password to be used for the backend",
			Sources:     cli.EnvVars("JWT_SECRET"),
			Destination: &params.JWTConfigValues.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       3,
			Usage:       "Maximum amount of hours for the tokens to expire",
			Sources:     cli.EnvVars("JWT_EXPIRE"),
			Destination: &params.JWTConfigValues.HoursToExpire,
		},
	}
}

// initOsqueryFlags initializes osquery-related flags
func initOsqueryFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "osquery-version",
			Value:       defOsqueryTablesVersion,
			Usage:       "Version of osquery to be used",
			Sources:     cli.EnvVars("OSQUERY_VERSION"),
			Destination: &params.OsqueryConfigValues.Version,
		},
		&cli.StringFlag{
			Name:        "osquery-tables-file",
			Value:       defOsqueryTablesFile,
			Usage:       "File with the osquery tables to be used",
			Sources:     cli.EnvVars("OSQUERY_TABLES"),
			Destination: &params.OsqueryConfigValues.TablesFile,
		},
		&cli.BoolFlag{
			Name:        "osquery-logger",
			Value:       true,
			Usage:       "Enable remote tls logger for osquery",
			Sources:     cli.EnvVars("OSQUERY_LOGGER"),
			Destination: &params.OsqueryConfigValues.Logger,
		},
		&cli.BoolFlag{
			Name:        "osquery-config",
			Value:       true,
			Usage:       "Enable remote tls config for osquery",
			Sources:     cli.EnvVars("OSQUERY_CONFIG"),
			Destination: &params.OsqueryConfigValues.Config,
		},
		&cli.BoolFlag{
			Name:        "osquery-query",
			Value:       true,
			Usage:       "Enable remote tls queries for osquery",
			Sources:     cli.EnvVars("OSQUERY_QUERY"),
			Destination: &params.OsqueryConfigValues.Query,
		},
		&cli.BoolFlag{
			Name:        "osquery-carve",
			Value:       true,
			Usage:       "Enable remote tls carver for osquery",
			Sources:     cli.EnvVars("OSQUERY_CARVE"),
			Destination: &params.OsqueryConfigValues.Carve,
		},
	}
}

// initAdminFlags initializes all the admin service specific flags
func initAdminFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "session-key",
			Value:       "",
			Usage:       "Session key to generate cookies from it",
			Sources:     cli.EnvVars("SESSION_KEY"),
			Destination: &params.ConfigValues.SessionKey,
		},
		&cli.StringFlag{
			Name:        "saml-file",
			Value:       defSAMLConfigurationFile,
			Usage:       "Load SAML configuration from `FILE`",
			Sources:     cli.EnvVars("SAML_CONFIG_FILE"),
			Destination: &params.SAMLConfigFile,
		},
		&cli.StringFlag{
			Name:        "static",
			Aliases:     []string{"s"},
			Value:       defStaticFilesFolder,
			Usage:       "Directory with all the static files needed for the osctrl-admin UI",
			Sources:     cli.EnvVars("STATIC_FILES"),
			Destination: &params.StaticFiles,
		},
		&cli.BoolFlag{
			Name:        "static-offline",
			Aliases:     []string{"S"},
			Value:       false,
			Usage:       "Use offline static files (js and css). Default is online files.",
			Sources:     cli.EnvVars("STATIC_ONLINE"),
			Destination: &params.StaticOffline,
		},
		&cli.StringFlag{
			Name:        "templates",
			Value:       defTemplatesFolder,
			Usage:       "Directory with all the templates needed for the osctrl-admin UI",
			Sources:     cli.EnvVars("TEMPLATES_DIR"),
			Destination: &params.TemplatesDir,
		},
		&cli.StringFlag{
			Name:        "carved",
			Value:       defCarvedFolder,
			Usage:       "Directory for all the received carved files from osquery",
			Sources:     cli.EnvVars("CARVED_FILES"),
			Destination: &params.CarvedDir,
		},
		&cli.StringFlag{
			Name:        "background-image",
			Aliases:     []string{"bg-img", "background"},
			Value:       defBackgroundImageFile,
			Usage:       "Background image file for all the pages in the osctrl-admin UI",
			Sources:     cli.EnvVars("BACKGROUND_IMAGE"),
			Destination: &params.BackgroundImage,
		},
		&cli.StringFlag{
			Name:        "branding-image",
			Aliases:     []string{"brand-img", "branding"},
			Value:       defBrandingImageFile,
			Usage:       "Branding image file for the osctrl-admin UI. Use an image with 450x130 pixels for best results.",
			Sources:     cli.EnvVars("BRANDING_IMAGE"),
			Destination: &params.BrandingImage,
		},
		&cli.BoolFlag{
			Name:        "audit-log",
			Aliases:     []string{"audit"},
			Value:       false,
			Usage:       "Enable audit log for the osctrl-admin UI. It will log all the user actions in the UI",
			Sources:     cli.EnvVars("AUDIT_LOG"),
			Destination: &params.AuditLog,
		},
	}
}

// initApiFlags initializes all the flags specific to the osctrl-api service
func initApiFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "audit-log",
			Aliases:     []string{"audit"},
			Value:       false,
			Usage:       "Enable audit log for the osctrl-api. It will log all the user actions in the API",
			Sources:     cli.EnvVars("AUDIT_LOG"),
			Destination: &params.AuditLog,
		},
	}
}

// initDebugFlags initializes all the debug logging specific flags
func initDebugFlags(params *ServiceFlagParams, service string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "enable-http-debug",
			Value:       false,
			Usage:       "Enable HTTP Debug mode to dump full HTTP incoming request",
			Sources:     cli.EnvVars("HTTP_DEBUG"),
			Destination: &params.DebugHTTPValues.Enabled,
		},
		&cli.StringFlag{
			Name:        "http-debug-file",
			Value:       "debug-http-" + service + ".log",
			Usage:       "File to dump the HTTP requests when HTTP Debug mode is enabled",
			Sources:     cli.EnvVars("HTTP_DEBUG_FILE"),
			Destination: &params.DebugHTTPValues.File,
		},
		&cli.BoolFlag{
			Name:        "http-debug-show-body",
			Value:       false,
			Usage:       "Show body of the HTTP requests when HTTP Debug mode is enabled",
			Sources:     cli.EnvVars("HTTP_DEBUG_SHOW_BODY"),
			Destination: &params.DebugHTTPValues.ShowBody,
		},
	}
}

// initOsctrldFlags initializes all the flags needed for the osctrld service
func initOsctrldFlags(params *ServiceFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "enable-osctrld",
			Value:       false,
			Usage:       "Enable osctrld endpoints and functionality.",
			Sources:     cli.EnvVars("OSCTRLD"),
			Destination: &params.OsctrldConfigValues.Enabled,
		},
	}
}
