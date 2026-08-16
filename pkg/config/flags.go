package config

import (
	"context"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/urfave/cli/v3"
)

// Default values
const (
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 10
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 10
	// Default JWT token expiration time in hours
	defJWTExpirationHours int = 3
)

// osquery
const (
	// osquery version to display tables
	defOsqueryTablesVersion = version.OsqueryVersion
	// JSON file with osquery tables data
	defOsqueryTablesFile string = "./data/" + defOsqueryTablesVersion + ".json"
	// Default TLS certificate file
	defTLSCertificateFile string = "./config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "./config/tls.key"
	// Default carved files folder
	defCarvedFolder string = "./carved_files/"
	// Default db filepath for sqlite
	defSQLiteDBFile string = "./osctrl.db"
)

// ServiceParameters to keep all service parameters from flags
type ServiceParameters struct {
	// Configuration will be loaded from a file
	ConfigFlag bool
	// Service configuration file
	ServiceConfigFile string
	// Service configuration values
	Service *YAMLConfigurationService
	// DB configuration values
	DB *YAMLConfigurationDB
	// Batch writer configuration values to handle bulk writes to the backend
	BatchWriter *YAMLConfigurationWriter
	// Redis configuration values
	Redis *YAMLConfigurationRedis
	// osquery configuration values
	Osquery *YAMLConfigurationOsquery
	// Config endpoints configuration values
	ConfigEndpoints *YAMLConfigurationEndpoints
	// osctrld configuration values
	Osctrld *YAMLConfigurationOsctrld
	// Metrics configuration values
	Metrics *YAMLConfigurationMetrics
	// SAML configuration values
	SAML *YAMLConfigurationSAML
	// OIDC configuration values
	OIDC *YAMLConfigurationOIDC
	// JWT configuration values
	JWT *YAMLConfigurationJWT
	// TLS configuration values
	TLS *YAMLConfigurationTLS
	// Logger configuration values
	Logger *YAMLConfigurationLogger
	// Carver configuration values
	Carver *YAMLConfigurationCarver
	// Debug configuration values
	Debug *YAMLConfigurationDebug
	// Rate limit configuration values
	RateLimits *YAMLConfigurationRateLimits
}

// initAuthFlag returns the per-service `--auth` flag with the given
// default and usage text. Kept out of initServiceFlags so each
// service can pick the default + help text that matches its
// semantics:
//
//   - osctrl-api uses JWT to authenticate operators / SPA clients,
//     and surfaces the OSCTRL_INSECURE_NO_AUTH env-var requirement
//     in `--help` so operators discover the opt-in path before
//     hitting the fatal guardAuthMode check at startup.
//   - osctrl-tls authenticates osquery agents via per-environment
//     enroll secret, not via this flag; AuthNone is correct for
//     it and the help text doesn't need additional notes.
func initAuthFlag(params *ServiceParameters, defaultValue string, usage string) cli.Flag {
	return &cli.StringFlag{
		Name:        "auth",
		Aliases:     []string{"A"},
		Value:       defaultValue,
		Usage:       usage,
		Sources:     cli.EnvVars("SERVICE_AUTH"),
		Destination: &params.Service.Auth,
	}
}

// InitTLSFlags initializes all the flags needed for the TLS service
func InitTLSFlags(params *ServiceParameters) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, initServiceFlags(params)...)
	allFlags = append(allFlags, initAuthFlag(params, AuthNone, "Authentication mechanism for the service"))
	allFlags = append(allFlags, initLoggingFlags(params)...)
	allFlags = append(allFlags, initMetricsFlags(params)...)
	allFlags = append(allFlags, initWriterFlags(params)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initOsctrldFlags(params)...)
	allFlags = append(allFlags, initOsqueryFlags(params)...)
	allFlags = append(allFlags, initCarverFlags(params)...)
	allFlags = append(allFlags, initRateLimitFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, initS3LoggingFlags(params)...)
	allFlags = append(allFlags, initKafkaFlags(params)...)
	allFlags = append(allFlags, initDebugFlags(params, ServiceTLS)...)
	allFlags = append(allFlags, &cli.BoolFlag{
		Name:        "db-health-check",
		Value:       false,
		Usage:       "Enable a background DB liveness monitor. After --db-health-threshold consecutive ping failures, EnvCache and SettingsCache switch to stale-serve mode (serve cached entries on DB miss, extend TTLs) so osquery nodes keep getting config/logs during a DB outage. Disabled by default.",
		Sources:     cli.EnvVars("DB_HEALTH_CHECK"),
		Destination: &params.Service.DBHealthCheck,
	},
		&cli.IntFlag{
			Name:        "db-health-interval",
			Value:       5,
			Usage:       "Seconds between DB health pings when --db-health-check is enabled.",
			Sources:     cli.EnvVars("DB_HEALTH_INTERVAL"),
			Destination: &params.Service.DBHealthInterval,
		},
		&cli.IntFlag{
			Name:        "db-health-threshold",
			Value:       3,
			Usage:       "Consecutive DB ping failures required before EnvCache and SettingsCache enter stale-serve mode.",
			Sources:     cli.EnvVars("DB_HEALTH_THRESHOLD"),
			Destination: &params.Service.DBHealthThreshold,
		})
	return allFlags
}

// InitAPIFlags initializes all the flags needed for the API service
func InitAPIFlags(params *ServiceParameters) []cli.Flag {
	var allFlags []cli.Flag
	// Add flags by category
	allFlags = append(allFlags, initConfigFlags(params, ServiceAPI)...)
	allFlags = append(allFlags, initServiceFlags(params)...)
	allFlags = append(allFlags, initAuthFlag(params, AuthJWT, "Authentication mechanism for the service (jwt|none — `none` requires OSCTRL_INSECURE_NO_AUTH=1)"))
	allFlags = append(allFlags, initLoggingFlags(params)...)
	allFlags = append(allFlags, initRedisFlags(params)...)
	allFlags = append(allFlags, initDBFlags(params)...)
	allFlags = append(allFlags, initTLSSecurityFlags(params)...)
	allFlags = append(allFlags, initJWTFlags(params)...)
	allFlags = append(allFlags, initOIDCFlags(params)...)
	allFlags = append(allFlags, initSAMLFlags(params)...)
	allFlags = append(allFlags, initOsqueryFlags(params)...)
	allFlags = append(allFlags, initCarverFlags(params)...)
	allFlags = append(allFlags, initRateLimitFlags(params, ServiceAPI)...)
	allFlags = append(allFlags, initDebugFlags(params, ServiceAPI)...)
	allFlags = append(allFlags, &cli.BoolFlag{
		Name:        "db-health-check",
		Value:       false,
		Usage:       "Enable a background DB liveness monitor. After --db-health-threshold consecutive ping failures, EnvCache switches to stale-serve mode (serve cached entries on DB miss, extend TTLs) so the API keeps responding to read-only env lookups during a DB outage. Disabled by default.",
		Sources:     cli.EnvVars("DB_HEALTH_CHECK"),
		Destination: &params.Service.DBHealthCheck,
	},
		&cli.IntFlag{
			Name:        "db-health-interval",
			Value:       5,
			Usage:       "Seconds between DB health pings when --db-health-check is enabled.",
			Sources:     cli.EnvVars("DB_HEALTH_INTERVAL"),
			Destination: &params.Service.DBHealthInterval,
		},
		&cli.IntFlag{
			Name:        "db-health-threshold",
			Value:       3,
			Usage:       "Consecutive DB ping failures required before EnvCache enters stale-serve mode.",
			Sources:     cli.EnvVars("DB_HEALTH_THRESHOLD"),
			Destination: &params.Service.DBHealthThreshold,
		})
	return allFlags
}

// initConfigFlags initializes configuration-related flags
func initConfigFlags(params *ServiceParameters, service string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via YAML file",
			Sources:     cli.EnvVars("SERVICE_CONFIG"),
			Destination: &params.ConfigFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       "./config/" + service + ".yml",
			Usage:       "Load service configuration from `FILE`",
			Sources:     cli.EnvVars("SERVICE_CONFIG_FILE"),
			Destination: &params.ServiceConfigFile,
		},
	}
}

// initServiceFlags initializes main service-related flags
func initServiceFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "127.0.0.1",
			Usage:       "Listener for the service",
			Sources:     cli.EnvVars("SERVICE_LISTENER"),
			Destination: &params.Service.Listener,
		},
		&cli.IntFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       9000,
			Usage:       "TCP port for the service",
			Sources:     cli.EnvVars("SERVICE_PORT"),
			Destination: &params.Service.Port,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "osctrl.net",
			Usage:       "Exposed hostname the service uses",
			Sources:     cli.EnvVars("SERVICE_HOST"),
			Destination: &params.Service.Host,
		},
		&cli.StringFlag{
			Name:        "log-level",
			Value:       LogLevelInfo,
			Usage:       "Log level for the service",
			Sources:     cli.EnvVars("SERVICE_LOG_LEVEL"),
			Destination: &params.Service.LogLevel,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Value:       LogFormatJSON,
			Usage:       "Log format for the service",
			Sources:     cli.EnvVars("SERVICE_LOG_FORMAT"),
			Destination: &params.Service.LogFormat,
		},
		&cli.BoolFlag{
			Name:        "audit-log",
			Aliases:     []string{"audit"},
			Value:       true,
			Usage:       "Enable audit log for the service. Logs sensitive actions (logins, env mutations, query/carve runs, etc.). Disable only for local dev — production deployments MUST keep this on so SoC tooling has a stream to alert on.",
			Sources:     cli.EnvVars("AUDIT_LOG"),
			Destination: &params.Service.AuditLog,
		},
		&cli.StringFlag{
			Name:        "trusted-proxies",
			Value:       "",
			Usage:       "Comma-separated CIDR list whose X-Real-IP / X-Forwarded-For headers will be honored. Empty (default) ignores forwarding headers and uses RemoteAddr verbatim — prevents header-spoofed rate-limit bypass and audit-log poisoning.",
			Sources:     cli.EnvVars("SERVICE_TRUSTED_PROXIES"),
			Destination: &params.Service.TrustedProxies,
		},
		&cli.StringFlag{
			Name:        "geoip-db",
			Value:       "",
			Usage:       "Path to a MaxMind GeoLite2-Country .mmdb file. When set, node IP addresses are resolved to country codes (shown as flag emojis in the SPA). Empty (default) disables GeoIP entirely.",
			Sources:     cli.EnvVars("SERVICE_GEOIP_DB"),
			Destination: &params.Service.GeoIPDBPath,
		},
		&cli.BoolFlag{
			Name:        "posture-enabled",
			Value:       false,
			Usage:       "Enable the security and compliance posture system. Disabled by default; when enabled osctrl-tls ingests posture query results and osctrl-api exposes posture endpoints to the SPA.",
			Sources:     cli.EnvVars("SERVICE_POSTURE_ENABLED"),
			Destination: &params.Service.PostureEnabled,
		},
		&cli.BoolFlag{
			Name:        "service-config-enabled",
			Value:       false,
			Usage:       "Serve the service-config API and show the matching section in the SPA. Disabled by default: the YAML sections are still seeded into the database at every boot and resolved back at startup, but none of the /api/v1/service-config routes are registered — change the rows or the YAML file directly instead.",
			Sources:     cli.EnvVars("SERVICE_CONFIG_ENABLED"),
			Destination: &params.Service.ServiceConfigEnabled,
		},
		&cli.BoolFlag{
			Name:        "mfa-required",
			Value:       false,
			Usage:       "Require a second authentication factor (TOTP, passkey or security key) for password logins. Users without one enroll at their next login. Service accounts and federated logins are unaffected.",
			Sources:     cli.EnvVars("SERVICE_MFA_REQUIRED"),
			Destination: &params.Service.MFARequired,
		},
		&cli.StringFlag{
			Name:        "mfa-issuer",
			Value:       "",
			Usage:       "Label shown next to the account in authenticator apps. Defaults to \"osctrl\".",
			Sources:     cli.EnvVars("SERVICE_MFA_ISSUER"),
			Destination: &params.Service.MFAIssuer,
		},
		&cli.StringFlag{
			Name:        "mfa-rpid",
			Value:       "",
			Usage:       "WebAuthn Relying Party ID — the registrable domain passkeys and security keys are bound to, no scheme or port. Empty uses --host. Changing it invalidates every registered credential.",
			Sources:     cli.EnvVars("SERVICE_MFA_RPID"),
			Destination: &params.Service.MFARPID,
		},
		&cli.StringFlag{
			Name:        "mfa-origins",
			Value:       "",
			Usage:       "Comma-separated origins the SPA is served from, with scheme and any non-default port. Empty uses https://<host>. A browser refuses a WebAuthn ceremony whose origin is not listed.",
			Sources:     cli.EnvVars("SERVICE_MFA_ORIGINS"),
			Destination: &params.Service.MFAOrigins,
		},
		&cli.StringFlag{
			Name:        "posture-query-prefix",
			Value:       "osctrl:posture:",
			Usage:       "Prefix for scheduled query names whose results are ingested as node posture data when --posture-enabled is true.",
			Sources:     cli.EnvVars("SERVICE_POSTURE_QUERY_PREFIX"),
			Destination: &params.Service.PostureQueryPrefix,
		},
	}
}

// initLoggingFlags initializes logging-related flags
func initLoggingFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "logger",
			Aliases:     []string{"L"},
			Value:       LoggingDB,
			Usage:       "Logger mechanism to handle status/result logs from nodes",
			Sources:     cli.EnvVars("SERVICE_LOGGER"),
			Destination: &params.Logger.Type,
		},
		&cli.StringFlag{
			Name:    "loggers",
			Usage:   "Logger mechanisms to handle status/result logs from nodes as a comma-separated list",
			Sources: cli.EnvVars("SERVICE_LOGGERS"),
			Action: func(_ context.Context, _ *cli.Command, v string) error {
				if v == "" {
					return nil
				}
				parts := strings.Split(v, ",")
				out := make([]string, 0, len(parts))
				for _, p := range parts {
					if p = strings.TrimSpace(p); p != "" {
						out = append(out, p)
					}
				}
				params.Logger.Types = out
				return nil
			},
		},
		&cli.BoolFlag{
			Name:        "logger-db-same",
			Value:       false,
			Usage:       "Use the same DB configuration for the logger",
			Sources:     cli.EnvVars("LOGGER_DB_SAME"),
			Destination: &params.Logger.LoggerDBSame,
		},
		&cli.BoolFlag{
			Name:        "always-log",
			Aliases:     []string{"a", "always"},
			Value:       false,
			Usage:       "Always log status and on-demand query logs from nodes in database",
			Sources:     cli.EnvVars("ALWAYS_LOG"),
			Destination: &params.Logger.AlwaysLog,
		},
	}
}

// initMetricsFlags initializes metrics-related flags
func initMetricsFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "metrics-listener",
			Value:       "127.0.0.1",
			Usage:       "Listener for prometheus metrics",
			Sources:     cli.EnvVars("METRICS_LISTENER"),
			Destination: &params.Metrics.Listener,
		},
		&cli.IntFlag{
			Name:        "metrics-port",
			Value:       9090,
			Usage:       "Port for exposing prometheus metrics",
			Sources:     cli.EnvVars("METRICS_PORT"),
			Destination: &params.Metrics.Port,
		},
		&cli.BoolFlag{
			Name:        "metrics-enabled",
			Value:       false,
			Usage:       "Enable prometheus metrics",
			Sources:     cli.EnvVars("METRICS_ENABLED"),
			Destination: &params.Metrics.Enabled,
		},
	}
}

// initWriterFlags initializes writer-related flags
func initWriterFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "writer-batch-size",
			Value:       50,
			Usage:       "Maximum number of events before flushing",
			Sources:     cli.EnvVars("WRITER_BATCH_SIZE"),
			Destination: &params.BatchWriter.WriterBatchSize,
		},
		&cli.DurationFlag{
			Name:        "writer-timeout",
			Value:       60 * time.Second,
			Usage:       "Maximum wait time before flushing",
			Sources:     cli.EnvVars("WRITER_TIMEOUT"),
			Destination: &params.BatchWriter.WriterTimeout,
		},
		&cli.IntFlag{
			Name:        "writer-buffer-size",
			Value:       2000,
			Usage:       "Size of the event channel buffer",
			Sources:     cli.EnvVars("WRITER_BUFFER_SIZE"),
			Destination: &params.BatchWriter.WriterBufferSize,
		},
	}
}

// initRedisFlags initializes Redis-related flags
func initRedisFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			Sources:     cli.EnvVars("REDIS_CONNECTION_STRING"),
			Destination: &params.Redis.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			Sources:     cli.EnvVars("REDIS_HOST"),
			Destination: &params.Redis.Host,
		},
		&cli.IntFlag{
			Name:        "redis-port",
			Value:       6379,
			Usage:       "Redis port to be connected to",
			Sources:     cli.EnvVars("REDIS_PORT"),
			Destination: &params.Redis.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			Sources:     cli.EnvVars("REDIS_PASS"),
			Destination: &params.Redis.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			Sources:     cli.EnvVars("REDIS_DB"),
			Destination: &params.Redis.DB,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			Sources:     cli.EnvVars("REDIS_CONN_RETRY"),
			Destination: &params.Redis.ConnRetry,
		},
	}
}

// initDBFlags initializes database-related flags
func initDBFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "db-type",
			Value:       "postgres",
			Usage:       "Type of backend to be used",
			Sources:     cli.EnvVars("DB_TYPE"),
			Destination: &params.DB.Type,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			Sources:     cli.EnvVars("DB_HOST"),
			Destination: &params.DB.Host,
		},
		&cli.IntFlag{
			Name:        "db-port",
			Value:       5432,
			Usage:       "Backend port to be connected to",
			Sources:     cli.EnvVars("DB_PORT"),
			Destination: &params.DB.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			Sources:     cli.EnvVars("DB_NAME"),
			Destination: &params.DB.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			Sources:     cli.EnvVars("DB_USER"),
			Destination: &params.DB.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			Sources:     cli.EnvVars("DB_PASS"),
			Destination: &params.DB.Password,
		},
		&cli.StringFlag{
			Name:        "db-sslmode",
			Value:       "disable",
			Usage:       "SSL native support to encrypt the connection to the backend",
			Sources:     cli.EnvVars("DB_SSLMODE"),
			Destination: &params.DB.SSLMode,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			Sources:     cli.EnvVars("DB_MAX_IDLE_CONNS"),
			Destination: &params.DB.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			Sources:     cli.EnvVars("DB_MAX_OPEN_CONNS"),
			Destination: &params.DB.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			Sources:     cli.EnvVars("DB_CONN_MAX_LIFETIME"),
			Destination: &params.DB.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			Sources:     cli.EnvVars("DB_CONN_RETRY"),
			Destination: &params.DB.ConnRetry,
		},
		&cli.StringFlag{
			Name:        "db-filepath",
			Value:       defSQLiteDBFile,
			Usage:       "File path to the SQLite database, only used when type is sqlite",
			Sources:     cli.EnvVars("DB_SQLITE_FILEPATH"),
			Destination: &params.DB.FilePath,
		},
	}
}

// initTLSSecurityFlags initializes TLS security-related flags
func initTLSSecurityFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			Sources:     cli.EnvVars("TLS_SERVER"),
			Destination: &params.TLS.Termination,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       defTLSCertificateFile,
			Usage:       "TLS termination certificate from `FILE`",
			Sources:     cli.EnvVars("TLS_CERTIFICATE"),
			Destination: &params.TLS.CertificateFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       defTLSKeyFile,
			Usage:       "TLS termination private key from `FILE`",
			Sources:     cli.EnvVars("TLS_KEY"),
			Destination: &params.TLS.KeyFile,
		},
	}
}

// initCarverFlags initializes carver-related flags
func initCarverFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "carver-type",
			Value:       CarverDB,
			Usage:       "Carver to be used to receive files extracted from nodes",
			Sources:     cli.EnvVars("CARVER_TYPE"),
			Destination: &params.Carver.Type,
		},
		&cli.StringFlag{
			Name:        "carver-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_BUCKET"),
			Destination: &params.Carver.S3.Bucket,
		},
		&cli.StringFlag{
			Name:        "carver-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_REGION"),
			Destination: &params.Carver.S3.Region,
		},
		&cli.StringFlag{
			Name:        "carve-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_KEY_ID"),
			Destination: &params.Carver.S3.AccessKey,
		},
		&cli.StringFlag{
			Name:        "carve-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for carves",
			Sources:     cli.EnvVars("CARVER_S3_SECRET"),
			Destination: &params.Carver.S3.SecretAccessKey,
		},
		&cli.StringFlag{
			Name:        "carver-local-dir",
			Value:       defCarvedFolder,
			Usage:       "Local directory to store carved files",
			Sources:     cli.EnvVars("CARVER_LOCAL_DIR"),
			Destination: &params.Carver.Local.CarvesDir,
		},
	}
}

// initRateLimitFlags initializes request rate-limit flags. Only currently
// rate-limited surfaces are exposed.
func initRateLimitFlags(params *ServiceParameters, service string) []cli.Flag {
	if params.RateLimits == nil {
		params.RateLimits = DefaultRateLimitsPtr()
	}
	if service == ServiceTLS {
		return rateLimitFlags("enroll", "RATE_LIMIT_ENROLL", &params.RateLimits.Enroll)
	}
	return append(
		append(
			rateLimitFlags("login", "RATE_LIMIT_LOGIN", &params.RateLimits.Login),
			rateLimitFlags("pre-auth", "RATE_LIMIT_PRE_AUTH", &params.RateLimits.PreAuth)...,
		),
		rateLimitFlags("service-config-apply", "RATE_LIMIT_SERVICE_CONFIG_APPLY", &params.RateLimits.ServiceConfigApply)...,
	)
}

func rateLimitFlags(name, envPrefix string, cfg *YAMLConfigurationRateLimit) []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:        "rate-limit-" + name + "-burst",
			Value:       cfg.Burst,
			Usage:       "Maximum burst for the " + name + " rate limiter",
			Sources:     cli.EnvVars(envPrefix + "_BURST"),
			Destination: &cfg.Burst,
		},
		&cli.DurationFlag{
			Name:        "rate-limit-" + name + "-period",
			Value:       cfg.Period,
			Usage:       "Refill period for the " + name + " rate limiter",
			Sources:     cli.EnvVars(envPrefix + "_PERIOD"),
			Destination: &cfg.Period,
		},
		&cli.DurationFlag{
			Name:        "rate-limit-" + name + "-evict-after",
			Value:       cfg.EvictAfter,
			Usage:       "Idle bucket eviction window for the " + name + " rate limiter",
			Sources:     cli.EnvVars(envPrefix + "_EVICT_AFTER"),
			Destination: &cfg.EvictAfter,
		},
		&cli.IntFlag{
			Name:        "rate-limit-" + name + "-retry-after",
			Value:       cfg.RetryAfter,
			Usage:       "Retry-After seconds returned by the " + name + " rate limiter",
			Sources:     cli.EnvVars(envPrefix + "_RETRY_AFTER"),
			Destination: &cfg.RetryAfter,
		},
		&cli.IntFlag{
			Name:        "rate-limit-" + name + "-max-buckets",
			Value:       cfg.MaxBuckets,
			Usage:       "Maximum per-key buckets for the " + name + " rate limiter; 0 uses the default",
			Sources:     cli.EnvVars(envPrefix + "_MAX_BUCKETS"),
			Destination: &cfg.MaxBuckets,
		},
	}
}

// initS3LoggingFlags initializes S3 logging-related flags
func initS3LoggingFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-s3-bucket",
			Value:       "",
			Usage:       "S3 bucket to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_BUCKET"),
			Destination: &params.Logger.S3.Bucket,
		},
		&cli.StringFlag{
			Name:        "log-s3-region",
			Value:       "",
			Usage:       "S3 region to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_REGION"),
			Destination: &params.Logger.S3.Region,
		},
		&cli.StringFlag{
			Name:        "log-s3-key-id",
			Value:       "",
			Usage:       "S3 access key id to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_KEY_ID"),
			Destination: &params.Logger.S3.AccessKey,
		},
		&cli.StringFlag{
			Name:        "log-s3-secret",
			Value:       "",
			Usage:       "S3 access key secret to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_S3_SECRET"),
			Destination: &params.Logger.S3.SecretAccessKey,
		},
	}
}

// initKafkaFlags initializes Kafka-related flags
func initKafkaFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-kafka-boostrap-servers",
			Value:       "",
			Usage:       "Kafka bootstrap servers to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_BOOTSTRAP_SERVERS"),
			Destination: &params.Logger.Kafka.BootstrapServer,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sslca-location",
			Value:       "",
			Usage:       "Kafka sslca location to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SSLCA_LOCATION"),
			Destination: &params.Logger.Kafka.SSLCALocation,
		},
		&cli.DurationFlag{
			Name:        "log-kafka-connection-timeout",
			Value:       5 * time.Second,
			Usage:       "Kafka connection timeout to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_CONNECTION_TIMEOUT"),
			Destination: &params.Logger.Kafka.ConnectionTimeout,
		},
		&cli.StringFlag{
			Name:        "log-kafka-topic",
			Value:       "",
			Usage:       "Kafka topic to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_TOPIC"),
			Destination: &params.Logger.Kafka.Topic,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-mechanism",
			Value:       "",
			Usage:       "Kafka sasl mechanism' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_MECHANISM"),
			Destination: &params.Logger.Kafka.SASL.Mechanism,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-username",
			Value:       "",
			Usage:       "Kafka sasl username' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_USERNAME"),
			Destination: &params.Logger.Kafka.SASL.Username,
		},
		&cli.StringFlag{
			Name:        "log-kafka-sasl-password",
			Value:       "",
			Usage:       "Kafka sasl password' to be used as configuration for logging",
			Sources:     cli.EnvVars("LOG_KAFKA_SASL_PASSWORD"),
			Destination: &params.Logger.Kafka.SASL.Password,
		},
	}
}

// initJWTFlags initializes JWT flags
func initJWTFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "jwt-secret",
			Usage:       "Password to be used for the backend",
			Sources:     cli.EnvVars("JWT_SECRET"),
			Destination: &params.JWT.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       defJWTExpirationHours,
			Usage:       "Maximum amount of hours for the tokens to expire",
			Sources:     cli.EnvVars("JWT_EXPIRE"),
			Destination: &params.JWT.HoursToExpire,
		},
	}
}

// initOIDCFlags initializes OIDC flags
func initOIDCFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "oidc-enabled",
			Usage:       "Enable the federated-login surface on osctrl-api",
			Sources:     cli.EnvVars("OIDC_ENABLED"),
			Destination: &params.OIDC.Enabled,
		},
		&cli.StringFlag{
			Name:        "oidc-issuer-url",
			Usage:       "OIDC issuer URL (the realm root, /.well-known/openid-configuration is appended automatically)",
			Sources:     cli.EnvVars("OIDC_ISSUER_URL"),
			Destination: &params.OIDC.IssuerURL,
		},
		&cli.StringFlag{
			Name:        "oidc-client-id",
			Usage:       "OIDC client ID registered with the IdP",
			Sources:     cli.EnvVars("OIDC_CLIENT_ID"),
			Destination: &params.OIDC.ClientID,
		},
		&cli.StringFlag{
			Name:        "oidc-client-secret",
			Usage:       "OIDC client secret",
			Sources:     cli.EnvVars("OIDC_CLIENT_SECRET"),
			Destination: &params.OIDC.ClientSecret,
		},
		&cli.StringFlag{
			Name:        "oidc-redirect-url",
			Usage:       "OIDC redirect URL — must match the IdP client config and end with /oidc/callback",
			Sources:     cli.EnvVars("OIDC_REDIRECT_URL"),
			Destination: &params.OIDC.RedirectURL,
		},
		&cli.StringFlag{
			Name:    "oidc-scopes",
			Usage:   "OIDC scopes as a comma-separated list (defaults to \"openid,profile,email\")",
			Sources: cli.EnvVars("OIDC_SCOPES"),
			Action: func(_ context.Context, _ *cli.Command, v string) error {
				if v == "" {
					return nil
				}
				parts := strings.Split(v, ",")
				out := make([]string, 0, len(parts))
				for _, p := range parts {
					if p = strings.TrimSpace(p); p != "" {
						out = append(out, p)
					}
				}
				params.OIDC.Scopes = out
				return nil
			},
		},
		&cli.StringFlag{
			Name:        "oidc-username-claim",
			Usage:       "ID-token claim used as the osctrl username (preferred_username, email, sub)",
			Sources:     cli.EnvVars("OIDC_USERNAME_CLAIM"),
			Destination: &params.OIDC.UsernameClaim,
		},
		&cli.StringFlag{
			Name:        "oidc-groups-claim",
			Usage:       "ID-token claim that contains group memberships (default: groups)",
			Sources:     cli.EnvVars("OIDC_GROUPS_CLAIM"),
			Destination: &params.OIDC.GroupsClaim,
		},
		&cli.StringFlag{
			Name:    "oidc-required-groups",
			Usage:   "Comma-separated list of groups — user must belong to at least one to log in",
			Sources: cli.EnvVars("OIDC_REQUIRED_GROUPS"),
			Action: func(_ context.Context, _ *cli.Command, v string) error {
				if v == "" {
					return nil
				}
				parts := strings.Split(v, ",")
				out := make([]string, 0, len(parts))
				for _, p := range parts {
					if p = strings.TrimSpace(p); p != "" {
						out = append(out, p)
					}
				}
				params.OIDC.RequiredGroups = out
				return nil
			},
		},
		&cli.BoolFlag{
			Name:        "oidc-jit-provision",
			Usage:       "Auto-create osctrl users on first OIDC login (as non-admin)",
			Sources:     cli.EnvVars("OIDC_JIT_PROVISION"),
			Destination: &params.OIDC.JITProvision,
		},
		&cli.BoolFlag{
			Name:        "oidc-use-pkce",
			Usage:       "Enable PKCE (S256) for the OIDC Authorization Code flow",
			Sources:     cli.EnvVars("OIDC_USE_PKCE"),
			Destination: &params.OIDC.UsePKCE,
		},
	}
}

// initSAMLFlags initializes SAML flags for osctrl-api. Mirrors the OIDC
// flag shape — operators flip --saml-enabled, point us at the IdP's
// metadata URL, and the rest comes from the metadata document (signing
// keys, SSO endpoint, etc.).
func initSAMLFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "saml-enabled",
			Usage:       "Enable the SAML 2.0 federated-login surface on osctrl-api",
			Sources:     cli.EnvVars("SAML_ENABLED"),
			Destination: &params.SAML.Enabled,
		},
		&cli.StringFlag{
			Name:        "saml-idp-metadata-url",
			Usage:       "URL to the IdP's SAML metadata document — fetched once at startup, signing certs + SSO endpoint discovered from it",
			Sources:     cli.EnvVars("SAML_IDP_METADATA_URL"),
			Destination: &params.SAML.MetaDataURL,
		},
		&cli.StringFlag{
			Name:        "saml-entity-id",
			Usage:       "SP entity ID — what the IdP knows us by (conventionally the metadata URL)",
			Sources:     cli.EnvVars("SAML_ENTITY_ID"),
			Destination: &params.SAML.EntityID,
		},
		&cli.StringFlag{
			Name:        "saml-acs-url",
			Usage:       "Assertion Consumer Service URL — where the IdP POSTs SAMLResponse (must end with /api/v1/auth/saml/acs)",
			Sources:     cli.EnvVars("SAML_ACS_URL"),
			Destination: &params.SAML.ACSURL,
		},
		&cli.BoolFlag{
			Name:        "saml-jit-provision",
			Usage:       "Auto-create osctrl users on first SAML login (as non-admin)",
			Sources:     cli.EnvVars("SAML_JIT_PROVISION"),
			Destination: &params.SAML.JITProvision,
		},
		&cli.StringFlag{
			Name:        "saml-username-attribute",
			Usage:       "SAML attribute (Name or FriendlyName) whose value becomes the osctrl username; empty = use NameID verbatim",
			Sources:     cli.EnvVars("SAML_USERNAME_ATTRIBUTE"),
			Destination: &params.SAML.UsernameAttribute,
		},
		&cli.StringFlag{
			Name:        "saml-signing-cert",
			Usage:       "Path to PEM cert used to sign outbound AuthnRequests (paired with --saml-signing-key); empty disables AuthnRequest signing",
			Sources:     cli.EnvVars("SAML_SIGNING_CERT"),
			Destination: &params.SAML.SigningCertPath,
		},
		&cli.StringFlag{
			Name:        "saml-signing-key",
			Usage:       "Path to PEM RSA private key used to sign outbound AuthnRequests (paired with --saml-signing-cert)",
			Sources:     cli.EnvVars("SAML_SIGNING_KEY"),
			Destination: &params.SAML.SigningKeyPath,
		},
		&cli.BoolFlag{
			Name:        "saml-force-authn",
			Usage:       "Force re-authentication at the IdP on every SAML login (defaults true; SLO substitute since v1 has no SAML SLO)",
			Sources:     cli.EnvVars("SAML_FORCE_AUTHN"),
			Destination: &params.SAML.ForceAuthn,
			Value:       true,
		},
		&cli.StringFlag{
			Name:        "saml-logout-url",
			Usage:       "IdP session-termination URL for SAML users (e.g. https://tenant.auth0.com/v2/logout) — the logout handler returns it so the SPA can end the IdP session",
			Sources:     cli.EnvVars("SAML_LOGOUT_URL"),
			Destination: &params.SAML.LogoutURL,
		},
	}
}

// initOsqueryFlags initializes osquery-related flags
func initOsqueryFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "osquery-version",
			Value:       defOsqueryTablesVersion,
			Usage:       "Version of osquery to be used",
			Sources:     cli.EnvVars("OSQUERY_VERSION"),
			Destination: &params.Osquery.Version,
		},
		&cli.StringFlag{
			Name:        "osquery-tables-file",
			Value:       defOsqueryTablesFile,
			Usage:       "File with the osquery tables to be used",
			Sources:     cli.EnvVars("OSQUERY_TABLES"),
			Destination: &params.Osquery.TablesFile,
		},
		&cli.BoolFlag{
			Name:        "osquery-logger",
			Value:       true,
			Usage:       "Enable remote tls logger for osquery",
			Sources:     cli.EnvVars("OSQUERY_LOGGER"),
			Destination: &params.Osquery.Logger,
		},
		&cli.BoolFlag{
			Name:        "osquery-config",
			Value:       true,
			Usage:       "Enable remote tls config for osquery",
			Sources:     cli.EnvVars("OSQUERY_CONFIG"),
			Destination: &params.Osquery.Config,
		},
		&cli.BoolFlag{
			Name:        "osquery-query",
			Value:       true,
			Usage:       "Enable remote tls queries for osquery",
			Sources:     cli.EnvVars("OSQUERY_QUERY"),
			Destination: &params.Osquery.Query,
		},
		&cli.BoolFlag{
			Name:        "osquery-carve",
			Value:       true,
			Usage:       "Enable remote tls carver for osquery",
			Sources:     cli.EnvVars("OSQUERY_CARVE"),
			Destination: &params.Osquery.Carve,
		},
		&cli.BoolFlag{
			Name:        "osquery-accelerated",
			Value:       false,
			Usage:       "Enable accelerated mode when returning distributed queries to osquery",
			Sources:     cli.EnvVars("OSQUERY_ACCELERATED"),
			Destination: &params.Osquery.Accelerated,
		},
		&cli.BoolFlag{
			Name:        "osquery-file-explorer",
			Value:       false,
			Usage:       "Enable on-demand node file explorer queries",
			Sources:     cli.EnvVars("OSQUERY_FILE_EXPLORER"),
			Destination: &params.Osquery.FileExplorer,
		},
		&cli.BoolFlag{
			Name:        "read-only-configuration",
			Value:       false,
			Usage:       "Disable configuration changes via admin or api services",
			Sources:     cli.EnvVars("OSQUERY_READ_ONLY"),
			Destination: &params.Osquery.ReadOnly,
		},
	}
}

// initDebugFlags initializes all the debug logging specific flags
func initDebugFlags(params *ServiceParameters, service string) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "enable-http-debug",
			Value:       false,
			Usage:       "Enable HTTP Debug mode to dump full HTTP incoming request",
			Sources:     cli.EnvVars("HTTP_DEBUG"),
			Destination: &params.Debug.EnableHTTP,
		},
		&cli.StringFlag{
			Name:        "http-debug-file",
			Value:       "./debug-http-" + service + ".log",
			Usage:       "File to dump the HTTP requests when HTTP Debug mode is enabled",
			Sources:     cli.EnvVars("HTTP_DEBUG_FILE"),
			Destination: &params.Debug.HTTPFile,
		},
		&cli.BoolFlag{
			Name:        "http-debug-show-body",
			Value:       false,
			Usage:       "Show body of the HTTP requests when HTTP Debug mode is enabled",
			Sources:     cli.EnvVars("HTTP_DEBUG_SHOW_BODY"),
			Destination: &params.Debug.ShowBody,
		},
		&cli.StringFlag{
			Name:        "http-debug-host",
			Value:       "",
			Usage:       "Only dump HTTP requests from the osquery node with this UUID / host_identifier (case-insensitive). Empty dumps everything when --enable-http-debug is set.",
			Sources:     cli.EnvVars("HTTP_DEBUG_HOST"),
			Destination: &params.Debug.TargetHostIdentifier,
		},
	}
}

// initOsctrldFlags initializes all the flags needed for the osctrld service
func initOsctrldFlags(params *ServiceParameters) []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:        "enable-osctrld",
			Value:       false,
			Usage:       "Enable osctrld endpoints and functionality.",
			Sources:     cli.EnvVars("OSCTRLD"),
			Destination: &params.Osctrld.Enabled,
		},
	}
}
