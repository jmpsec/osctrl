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
	"github.com/urfave/cli/v3"
)

const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + config.ServiceTLS
	// Service description
	serviceDescription string = "TLS service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default accelerate interval in seconds
	defaultAccelerate int = 60
	// Default expiration of oneliners for enroll/expire
	defaultOnelinerExpiration bool = true
)

// Build-time metadata (overridden via -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...")
var (
	buildVersion = version.OsctrlVersion
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// Global variables
var (
	err                  error
	db                   *backend.DBManager
	redis                *cache.RedisManager
	settingsmgr          *settings.Settings
	envs                 *environments.EnvManager
	envsmap              environments.MapEnvironments
	settingsmap          settings.MapSettings
	nodesmgr             *nodes.NodeManager
	queriesmgr           *queries.Queries
	filecarves           *carves.Carves
	loggerTLS            *logging.LoggerTLS
	handlersTLS          *handlers.HandlersTLS
	tagsmgr              *tags.TagManager
	carvers3             *carves.CarverS3
	app                  *cli.Command
	flags                []cli.Flag
	serviceConfiguration config.TLSConfiguration
	// FIXME this struct is temporary until we refactor to write settings to the DB
	flagParams *config.ServiceParameters
)

// Function to load the configuration from a single YAML file
func loadYAMLConfiguration(file string) (config.TLSConfiguration, error) {
	var cfg config.TLSConfiguration
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
	if err := config.ValidateTLSConfigValues(cfg); err != nil {
		return cfg, err
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize default flagParams
	flagParams = &config.ServiceParameters{
		Service:     &config.YAMLConfigurationService{},
		DB:          &config.YAMLConfigurationDB{},
		BatchWriter: &config.YAMLConfigurationWriter{},
		Redis:       &config.YAMLConfigurationRedis{},
		Osquery:     &config.YAMLConfigurationOsquery{},
		Osctrld:     &config.YAMLConfigurationOsctrld{},
		Metrics:     &config.YAMLConfigurationMetrics{},
		TLS:         &config.YAMLConfigurationTLS{},
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
	flags = config.InitTLSFlags(flagParams)
}

// Go go!
func osctrlService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	// Attempt to connect to backend waiting until is ready
	for {
		log.Debug().Msgf("Creating DB manager with %v", flagParams.DB)
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
	// Attempt to connect to cache waiting until is ready
	for {
		log.Debug().Msgf("Creating Redis manager with %v", flagParams.Redis)
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
		log.Debug().Msgf("Cache NOT ready! Retrying in %d seconds...\n", flagParams.Redis.ConnRetry)
		time.Sleep(time.Duration(flagParams.Redis.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize environment")
	envs = environments.CreateEnvironment(db.Conn)
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Info().Msg("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Info().Msg("Initialize carves")
	filecarves = carves.CreateFileCarves(db.Conn, flagParams.Carver.Type, carvers3)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
	// Initialize batch writer
	log.Info().Msg("Initializing batch writer")
	tlsWriter := handlers.NewBatchWriter(
		flagParams.BatchWriter.WriterBatchSize,
		flagParams.BatchWriter.WriterTimeout,
		flagParams.BatchWriter.WriterBufferSize,
		*nodesmgr,
	)
	// Initialize service metrics
	log.Info().Msg("Loading service metrics")
	// Initialize TLS logger
	log.Info().Msg("Loading TLS logger")
	loggerTLS, err = logging.CreateLoggerTLS(*flagParams, settingsmgr, nodesmgr, queriesmgr)
	if err != nil {
		log.Fatal().Msgf("Error loading logger - %s: %v", flagParams.Logger.Type, err)
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
			log.Debug().Msg("Refreshing environments")
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
			log.Debug().Msg("Refreshing settings")
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	if flagParams.Metrics.Enabled {
		log.Info().Msg("Metrics are enabled")
		// Register Prometheus metrics
		handlers.RegisterMetrics(prometheus.DefaultRegisterer)
		cache.RegisterMetrics(prometheus.DefaultRegisterer)
		// Creating a new prometheus service
		prometheusServer := http.NewServeMux()
		prometheusServer.Handle("/metrics", promhttp.Handler())
		go func() {
			log.Info().Msgf("Starting prometheus server at %s:%d", flagParams.Metrics.Listener, flagParams.Metrics.Port)
			err := http.ListenAndServe(flagParams.Metrics.Listener+":"+strconv.Itoa(flagParams.Metrics.Port), prometheusServer)
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
		handlers.WithOsqueryValues(flagParams.Osquery),
		handlers.WithDebugHTTP(flagParams.Debug),
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
	if flagParams.Osquery.Config {
		muxTLS.Handle("POST /{env}/"+environments.DefaultConfigPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.ConfigHandler)))
	}
	if flagParams.Osquery.Logger {
		muxTLS.Handle("POST /{env}/"+environments.DefaultLogPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.LogHandler)))
	}
	if flagParams.Osquery.Query {
		muxTLS.Handle("POST /{env}/"+environments.DefaultQueryReadPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.QueryReadHandler)))
		muxTLS.Handle("POST /{env}/"+environments.DefaultQueryWritePath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.QueryWriteHandler)))
	}
	if flagParams.Osquery.Carve {
		muxTLS.Handle("POST /{env}/"+environments.DefaultCarverInitPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.CarveInitHandler)))
		muxTLS.Handle("POST /{env}/"+environments.DefaultCarverBlockPath, handlersTLS.PrometheusMiddleware(http.HandlerFunc(handlersTLS.CarveBlockHandler)))
	}
	// TLS: Quick enroll/remove script
	muxTLS.HandleFunc("GET /{env}/{secretpath}/{script}", handlersTLS.QuickEnrollHandler)
	// TLS: Download enrolling package
	muxTLS.HandleFunc("GET /{env}/{secretpath}/package/{package}", handlersTLS.EnrollPackageHandler)

	// Enable osctrld endpoints
	if flagParams.Osctrld.Enabled {
		log.Info().Msg("Enabling osctrld endpoints")
		// TLS: osctrld retrieve flags
		muxTLS.HandleFunc("POST /{env}/"+environments.DefaultFlagsPath, handlersTLS.FlagsHandler)
		// TLS: osctrld retrieve certificate
		muxTLS.HandleFunc("POST /{env}/"+environments.DefaultCertPath, handlersTLS.CertHandler)
		// TLS: osctrld verification
		muxTLS.HandleFunc("POST /{env}/"+environments.DefaultVerifyPath, handlersTLS.VerifyHandler)
		// TLS: osctrld retrieve script to install/remove osquery
		muxTLS.HandleFunc("POST /{env}/{action}/{platform}/"+environments.DefaultScriptPath, handlersTLS.ScriptHandler)
	}

	// ////////////////////////////// Everything is ready at this point!
	serviceListener := flagParams.Service.Listener + ":" + strconv.Itoa(flagParams.Service.Port)
	if flagParams.TLS.Termination {
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
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := srv.ListenAndServeTLS(flagParams.TLS.CertificateFile, flagParams.TLS.KeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := http.ListenAndServe(serviceListener, muxTLS); err != nil {
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
						Value:   "config/" + config.ServiceTLS + ".yml",
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
						Value:   "config/" + config.ServiceTLS + ".yml",
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
					if err := config.GenerateTLSConfigFile(file, flagParams, cmd.Bool("force")); err != nil {
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
			// Service starts!
			osctrlService()
			return nil
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("app.Run error: %s", err.Error())
		os.Exit(1)
	}
}
