package config

import (
	"time"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/urfave/cli/v2"
)

// Deault values
const (
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// TLSFlagParams stores flag values for the TLS service
type TLSFlagParams struct {
	// Config flags
	ConfigFlag        bool
	ServiceConfigFile string
	RedisConfigFile   string
	DBFlag            bool
	RedisFlag         bool
	DBConfigFile      string

	// TLS Server flags
	TLSServer   bool
	TLSCertFile string
	TLSKeyFile  string

	// Logger flags
	LoggerFile   string
	LoggerDBSame bool
	AlwaysLog    bool

	// Carver flags
	CarverConfigFile string

	// Configuration values
	TLSConfigValues    JSONConfigurationTLS
	TLSWriterConfig    JSONConfigurationTLSWriter
	DBConfigValues     backend.JSONConfigurationDB
	RedisConfigValues  cache.JSONConfigurationRedis
	S3LogConfig        S3Configuration
	S3CarverConfig     S3Configuration
	KafkaConfiguration KafkaConfiguration
}

// InitTLSFlags initializes all the flags needed for the TLS service
func InitTLSFlags(params *TLSFlagParams) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params)...)
	allFlags = append(allFlags, initTLSServiceFlags(params)...)
	allFlags = append(allFlags, initLoggingFlags(params)...)
	allFlags = append(allFlags, initMetricsFlags(params)...)
	allFlags = append(allFlags, initWriterFlags(params)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initCarverFlags(params)...)
	allFlags = append(allFlags, initS3LoggingFlags(params)...)
	allFlags = append(allFlags, initKafkaFlags(params)...)
	return allFlags
}

// initConfigFlags initializes configuration-related flags
func initConfigFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via JSON file",
			EnvVars:     []string{"SERVICE_CONFIG"},
			Destination: &params.ConfigFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       "config/" + ServiceTLS + ".json",
			Usage:       "Load service configuration from `FILE`",
			EnvVars:     []string{"SERVICE_CONFIG_FILE"},
			Destination: &params.ServiceConfigFile,
		},
	}
}

// initTLSServiceFlags initializes TLS service-related flags
func initTLSServiceFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &params.TLSConfigValues.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9000",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &params.TLSConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &params.TLSConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &params.TLSConfigValues.Auth,
		},
	}
}

// initLoggingFlags initializes logging-related flags
func initLoggingFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			Value:       LogLevelInfo,
			Usage:       "Log level for the service",
			EnvVars:     []string{"SERVICE_LOG_LEVEL"},
			Destination: &params.TLSConfigValues.LogLevel,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Value:       LogFormatJSON,
			Usage:       "Log format for the service",
			EnvVars:     []string{"SERVICE_LOG_FORMAT"},
			Destination: &params.TLSConfigValues.LogFormat,
		},
		&cli.StringFlag{
			Name:        "logger",
			Aliases:     []string{"L"},
			Value:       LoggingDB,
			Usage:       "Logger mechanism to handle status/result logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &params.TLSConfigValues.Logger,
		},
		&cli.StringFlag{
			Name:        "logger-file",
			Aliases:     []string{"F"},
			Value:       "config/logger_tls.json",
			Usage:       "Logger configuration to handle status/results logs from nodes",
			EnvVars:     []string{"LOGGER_FILE"},
			Destination: &params.LoggerFile,
		},
		&cli.BoolFlag{
			Name:        "logger-db-same",
			Value:       false,
			Usage:       "Use the same DB configuration for the logger",
			EnvVars:     []string{"LOGGER_DB_SAME"},
			Destination: &params.LoggerDBSame,
		},
		&cli.BoolFlag{
			Name:        "always-log",
			Aliases:     []string{"a", "always"},
			Value:       false,
			Usage:       "Always log status and on-demand query logs from nodes in database",
			EnvVars:     []string{"ALWAYS_LOG"},
			Destination: &params.AlwaysLog,
		},
	}
}

// initMetricsFlags initializes metrics-related flags
func initMetricsFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "metrics-listener",
			Value:       "0.0.0.0",
			Usage:       "Listener for prometheus metrics",
			EnvVars:     []string{"METRICS_LISTENER"},
			Destination: &params.TLSConfigValues.MetricsListener,
		},
		&cli.StringFlag{
			Name:        "metrics-port",
			Value:       "9090",
			Usage:       "Port for exposing prometheus metrics",
			EnvVars:     []string{"METRICS_PORT"},
			Destination: &params.TLSConfigValues.MetricsPort,
		},
		&cli.BoolFlag{
			Name:        "metrics-enabled",
			Value:       false,
			Usage:       "Enable prometheus metrics",
			EnvVars:     []string{"METRICS_ENABLED"},
			Destination: &params.TLSConfigValues.MetricsEnabled,
		},
	}
}

// initWriterFlags initializes writer-related flags
func initWriterFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "writer-batch-size",
			Value:       50,
			Usage:       "Maximum number of events before flushing",
			EnvVars:     []string{"WRITER_BATCH_SIZE"},
			Destination: &params.TLSWriterConfig.WriterBatchSize,
		},
		&cli.DurationFlag{
			Name:        "writer-timeout",
			Value:       60 * time.Second,
			Usage:       "Maximum wait time before flushing",
			EnvVars:     []string{"WRITER_TIMEOUT"},
			Destination: &params.TLSWriterConfig.WriterTimeout,
		},
		&cli.IntFlag{
			Name:        "writer-buffer-size",
			Value:       2000,
			Usage:       "Size of the event channel buffer",
			EnvVars:     []string{"WRITER_BUFFER_SIZE"},
			Destination: &params.TLSWriterConfig.WriterBufferSize,
		},
	}
}

// initRedisFlags initializes Redis-related flags
func initRedisFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "redis",
			Aliases:     []string{"r"},
			Value:       false,
			Usage:       "Provide redis configuration via JSON file",
			EnvVars:     []string{"REDIS_CONFIG"},
			Destination: &params.RedisFlag,
		},
		&cli.StringFlag{
			Name:        "redis-file",
			Aliases:     []string{"R"},
			Value:       "config/redis.json",
			Usage:       "Load redis configuration from `FILE`",
			EnvVars:     []string{"REDIS_CONFIG_FILE"},
			Destination: &params.RedisConfigFile,
		},
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			EnvVars:     []string{"REDIS_CONNECTION_STRING"},
			Destination: &params.RedisConfigValues.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			EnvVars:     []string{"REDIS_HOST"},
			Destination: &params.RedisConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "redis-port",
			Value:       "6379",
			Usage:       "Redis port to be connected to",
			EnvVars:     []string{"REDIS_PORT"},
			Destination: &params.RedisConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			EnvVars:     []string{"REDIS_PASS"},
			Destination: &params.RedisConfigValues.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			EnvVars:     []string{"REDIS_DB"},
			Destination: &params.RedisConfigValues.DB,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"REDIS_CONN_RETRY"},
			Destination: &params.RedisConfigValues.ConnRetry,
		},
	}
}

// initDBFlags initializes database-related flags
func initDBFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &params.DBFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       "config/db.json",
			Usage:       "Load DB configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &params.DBConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &params.DBConfigValues.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &params.DBConfigValues.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &params.DBConfigValues.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &params.DBConfigValues.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &params.DBConfigValues.Password,
		},
		&cli.StringFlag{
			Name:        "db-sslmode",
			Value:       "disable",
			Usage:       "SSL native support to encrypt the connection to the backend",
			EnvVars:     []string{"DB_SSLMODE"},
			Destination: &params.DBConfigValues.SSLMode,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &params.DBConfigValues.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &params.DBConfigValues.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &params.DBConfigValues.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"DB_CONN_RETRY"},
			Destination: &params.DBConfigValues.ConnRetry,
		},
	}
}

// initTLSSecurityFlags initializes TLS security-related flags
func initTLSSecurityFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			EnvVars:     []string{"TLS_SERVER"},
			Destination: &params.TLSServer,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       "config/tls.crt",
			Usage:       "TLS termination certificate from `FILE`",
			EnvVars:     []string{"TLS_CERTIFICATE"},
			Destination: &params.TLSCertFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       "config/tls.key",
			Usage:       "TLS termination private key from `FILE`",
			EnvVars:     []string{"TLS_KEY"},
			Destination: &params.TLSKeyFile,
		},
	}
}

// initCarverFlags initializes carver-related flags
func initCarverFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_TYPE"},
			Destination: &params.TLSConfigValues.Carver,
		},
		&cli.StringFlag{
			Name:        "carver-file",
			Value:       "config/carver_tls.json",
			Usage:       "Carver configuration file to receive files extracted from nodes",
			EnvVars:     []string{"CARVER_FILE"},
			Destination: &params.CarverConfigFile,
		},
		&cli.StringFlag{
			Name:        "carver-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_BUCKET"},
			Destination: &params.S3CarverConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "carver-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_REGION"},
			Destination: &params.S3CarverConfig.Region,
		},
		&cli.StringFlag{
			Name:        "carve-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_KEY_ID"},
			Destination: &params.S3CarverConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "carve-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for carves",
			EnvVars:     []string{"CARVER_S3_SECRET"},
			Destination: &params.S3CarverConfig.SecretAccessKey,
		},
	}
}

// initS3LoggingFlags initializes S3 logging-related flags
func initS3LoggingFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_BUCKET"},
			Destination: &params.S3LogConfig.Bucket,
		},
		&cli.StringFlag{
			Name:        "log-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_REGION"},
			Destination: &params.S3LogConfig.Region,
		},
		&cli.StringFlag{
			Name:        "log-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_KEY_ID"},
			Destination: &params.S3LogConfig.AccessKey,
		},
		&cli.StringFlag{
			Name:        "log-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for logging",
			EnvVars:     []string{"LOG_S3_SECRET"},
			Destination: &params.S3LogConfig.SecretAccessKey,
		},
	}
}

// initKafkaFlags initializes Kafka-related flags
func initKafkaFlags(params *TLSFlagParams) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-kafka-boostrap-servers",
			Value:       "",
			Usage:       "Kafka bootstrap servers to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_BOOTSTRAP_SERVERS"},
			Destination: &params.KafkaConfiguration.BoostrapServer,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sslca-location",
			Value:       "",
			Usage:       "Kafka sslca location to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SSLCA_LOCATION"},
			Destination: &params.KafkaConfiguration.SSLCALocation,
		},
		&cli.DurationFlag{
			Name:        "log-kafka-connection-timeout",
			Value:       5 * time.Second,
			Usage:       "Kafka connection timeout to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_CONNECTION_TIMEOUT"},
			Destination: &params.KafkaConfiguration.ConnectionTimeout,
		},
		&cli.StringFlag{
			Name:        "log-kafka-topic",
			Value:       "",
			Usage:       "Kafka topic to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_TOPIC"},
			Destination: &params.KafkaConfiguration.Topic,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-mechanism",
			Value:       "",
			Usage:       "Kafka sasl mechanism' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_MECHANISM"},
			Destination: &params.KafkaConfiguration.SASL.Mechanism,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-username",
			Value:       "",
			Usage:       "Kafka sasl username' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_USERNAME"},
			Destination: &params.KafkaConfiguration.SASL.Username,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-password",
			Value:       "",
			Usage:       "Kafka sasl password' to be used as configuration for logging",
			EnvVars:     []string{"LOG_KAFKA_SASL_PASSWORD"},
			Destination: &params.KafkaConfiguration.SASL.Password,
		},
	}
}
