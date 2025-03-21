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
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
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
	serviceName string = projectName + "-" + config.ServiceTLS
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
	defConfigurationFile string = "config/" + config.ServiceTLS + ".json"
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
)

// Global variables
var (
	err         error
	db          *backend.DBManager
	redis       *cache.RedisManager
	settingsmgr *settings.Settings
	envs        *environments.Environment
	envsmap     environments.MapEnvironments
	settingsmap settings.MapSettings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	loggerTLS   *logging.LoggerTLS
	handlersTLS *handlers.HandlersTLS
	tagsmgr     *tags.TagManager
	carvers3    *carves.CarverS3
	app         *cli.App
	flags       []cli.Flag
	flagParams  config.TLSFlagParams
)

// Valid values for authentication in configuration
var validAuth = map[string]bool{
	config.AuthNone: true,
}

// Valid values for logging in configuration
var validLogging = map[string]bool{
	config.LoggingNone:     true,
	config.LoggingStdout:   true,
	config.LoggingFile:     true,
	config.LoggingDB:       true,
	config.LoggingGraylog:  true,
	config.LoggingSplunk:   true,
	config.LoggingLogstash: true,
	config.LoggingKinesis:  true,
	config.LoggingS3:       true,
	config.LoggingElastic:  true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	config.CarverDB:    true,
	config.CarverLocal: true,
	config.CarverS3:    true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file, service string) (config.JSONConfigurationTLS, error) {
	var cfg config.JSONConfigurationTLS
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
	// Initialize CLI flags using the config package
	flagParams = config.TLSFlagParams{
		ServiceConfigFile: defConfigurationFile,
		DBConfigFile:      defDBConfigurationFile,
		RedisConfigFile:   defRedisConfigurationFile,
		LoggerFile:        defLoggerConfigurationFile,
		CarverConfigFile:  defCarverConfigurationFile,
		TLSCertFile:       defTLSCertificateFile,
		TLSKeyFile:        defTLSKeyFile,
	}
	flags = config.InitTLSFlags(&flagParams)
}

// Go go!
func osctrlService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	// Attempt to connect to backend waiting until is ready
	for {
		db, err = backend.CreateDBManager(flagParams.DBConfigValues)
		if db != nil {
			log.Info().Msg("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to backend")
			if flagParams.DBConfigValues.ConnRetry == 0 {
				log.Fatal().Msg("Connection to backend failed and no retry was set")
			}
		}
		log.Info().Msgf("Backend NOT ready! Retrying in %d seconds...\n", flagParams.DBConfigValues.ConnRetry)
		time.Sleep(time.Duration(flagParams.DBConfigValues.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Info().Msg("Initializing cache...")
	// Attempt to connect to cache waiting until is ready
	for {
		redis, err = cache.CreateRedisManager(flagParams.RedisConfigValues)
		if redis != nil {
			log.Info().Msg("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to cache")
			if flagParams.RedisConfigValues.ConnRetry == 0 {
				log.Fatal().Msg("Connection to cache failed and no retry was set")
			}
		}
		log.Debug().Msgf("Cache NOT ready! Retrying in %d seconds...\n", flagParams.RedisConfigValues.ConnRetry)
		time.Sleep(time.Duration(flagParams.RedisConfigValues.ConnRetry) * time.Second)
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
	filecarves = carves.CreateFileCarves(db.Conn, flagParams.TLSConfigValues.Carver, carvers3)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams.TLSConfigValues); err != nil {
		log.Fatal().Msgf("Error loading settings - %s: %v", flagParams.TLSConfigValues.Logger, err)
	}
	// Initialize batch writer
	log.Info().Msg("Initializing batch writer")
	tlsWriter := handlers.NewBatchWriter(
		flagParams.TLSWriterConfig.WriterBatchSize,
		flagParams.TLSWriterConfig.WriterTimeout,
		flagParams.TLSWriterConfig.WriterBufferSize,
		*nodesmgr,
	)
	// Initialize service metrics
	log.Info().Msg("Loading service metrics")
	// Initialize TLS logger
	log.Info().Msg("Loading TLS logger")
	loggerTLS, err = logging.CreateLoggerTLS(flagParams, settingsmgr, nodesmgr, queriesmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading logger - %s: %v", flagParams.TLSConfigValues.Logger, err)
	}
	// Sleep to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Info().Msg("Preparing pseudo-cache for environments")
	go func() {
		_t := settingsmgr.RefreshEnvs(config.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(config.ServiceTLS) {
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
		_t := settingsmgr.RefreshSettings(config.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(config.ServiceTLS) {
				log.Info().Msg("DebugService: Refreshing settings")
			}
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	if flagParams.TLSConfigValues.MetricsEnabled {
		log.Info().Msg("Metrics are enabled")
		// Register Prometheus metrics
		handlers.RegisterMetrics(prometheus.DefaultRegisterer)

		// Creating a new prometheus service
		prometheusServer := http.NewServeMux()
		prometheusServer.Handle("/metrics", promhttp.Handler())

		go func() {
			log.Info().Msgf("Starting prometheus server at %s:%s", flagParams.TLSConfigValues.MetricsListener, flagParams.TLSConfigValues.MetricsPort)
			err := http.ListenAndServe(flagParams.TLSConfigValues.MetricsListener+":"+flagParams.TLSConfigValues.MetricsPort, prometheusServer)
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
		handlers.WithLogs(loggerTLS),
		handlers.WithWriteHandler(tlsWriter),
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
	serviceListener := flagParams.TLSConfigValues.Listener + ":" + flagParams.TLSConfigValues.Port
	if flagParams.TLSServer {
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
		if err := srv.ListenAndServeTLS(flagParams.TLSCertFile, flagParams.TLSKeyFile); err != nil {
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
	if flagParams.ConfigFlag {
		flagParams.TLSConfigValues, err = loadConfiguration(flagParams.ServiceConfigFile, config.ServiceTLS)
		if err != nil {
			return fmt.Errorf("Error loading %s - %w", flagParams.ServiceConfigFile, err)
		}
	}
	// Load db configuration if external JSON config file is used
	if flagParams.DBFlag {
		flagParams.DBConfigValues, err = backend.LoadConfiguration(flagParams.DBConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %w", err)
		}
	}
	// Load redis configuration if external JSON config file is used
	if flagParams.RedisFlag {
		flagParams.RedisConfigValues, err = cache.LoadConfiguration(flagParams.RedisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("Failed to load redis configuration - %w", err)
		}
	}
	// Load carver configuration if external JSON config file is used
	if flagParams.TLSConfigValues.Carver == config.CarverS3 {
		if flagParams.S3CarverConfig.Bucket != "" {
			carvers3, err = carves.CreateCarverS3(flagParams.S3CarverConfig)
		} else {
			carvers3, err = carves.CreateCarverS3File(flagParams.CarverConfigFile)
		}
		if err != nil {
			return fmt.Errorf("Failed to initiate s3 carver - %w", err)
		}
	}
	return nil
}

// Initialize service logger, set log level and format
func initializeLogger(logLevel, logFormat string) {
	// Log level
	switch strings.ToLower(logLevel) {
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
	// Log format
	switch strings.ToLower(logFormat) {
	case config.LogFormatJSON:
		log.Logger = log.With().Caller().Logger()
	case config.LogFormatConsole:
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
	initializeLogger(flagParams.TLSConfigValues.LogLevel, flagParams.TLSConfigValues.LogFormat)
	// Service starts!
	osctrlService()
}
