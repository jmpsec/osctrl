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

	"github.com/jmpsec/osctrl/cmd/api/handlers"
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
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"

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
	err         error
	db          *backend.DBManager
	redis       *cache.RedisManager
	apiUsers    *users.UserManager
	tagsmgr     *tags.TagManager
	settingsmgr *settings.Settings
	envs        *environments.EnvManager
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	handlersApi *handlers.HandlersApi
	app         *cli.App
	flags       []cli.Flag
	flagParams  config.ServiceFlagParams
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	config.AuthNone: true,
	config.AuthJWT:  true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file, service string) (config.JSONConfigurationService, error) {
	var cfg config.JSONConfigurationService
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
	// Initialize CLI flags using the config package
	flags = config.InitAdminFlags(&flagParams)
}

// Go go!
func osctrlAPIService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
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
		log.Info().Msgf("Cache NOT ready! Retrying in %d seconds...\n", flagParams.RedisConfigValues.ConnRetry)
		time.Sleep(time.Duration(flagParams.RedisConfigValues.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize users")
	apiUsers = users.CreateUserManager(db.Conn, &flagParams.JWTConfigValues)
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
	filecarves = carves.CreateFileCarves(db.Conn, flagParams.ConfigValues.Carver, nil)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams.ConfigValues); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
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
		handlers.WithCache(redis),
		handlers.WithVersion(buildVersion),
		handlers.WithName(serviceName),
		handlers.WithDebugHTTP(&flagParams.DebugHTTPValues),
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
	muxAPI.Handle(
		"POST "+_apiPath(apiLoginPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.LoginHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// ///////////////////////// AUTHENTICATED
	// API: check status
	muxAPI.HandleFunc("GET "+_apiPath(checksAuthPath), handlersApi.CheckHandlerAuth)
	// API: nodes by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/all",
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllNodesHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/active",
		handlerAuthCheck(http.HandlerFunc(handlersApi.ActiveNodesHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/inactive",
		handlerAuthCheck(http.HandlerFunc(handlersApi.InactiveNodesHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiNodesPath)+"/{env}/node/{node}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.NodeHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/{env}/delete",
		handlerAuthCheck(http.HandlerFunc(handlersApi.DeleteNodeHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/{env}/tag",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagNodeHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiNodesPath)+"/lookup",
		handlerAuthCheck(http.HandlerFunc(handlersApi.LookupNodeHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: queries by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiQueriesPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiQueriesPath)+"/{env}/list/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.QueryListHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiQueriesPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesRunHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiQueriesPath)+"/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.QueryShowHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiQueriesPath)+"/{env}/results/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.QueryResultsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiAllQueriesPath+"/{env}"),
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllQueriesShowHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiQueriesPath)+"/{env}/{action}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.QueriesActionHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: carves by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiCarvesPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarveShowHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiCarvesPath)+"/{env}/queries/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarveQueriesHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiCarvesPath)+"/{env}/list",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarveListHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiCarvesPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesRunHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiCarvesPath)+"/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarveShowHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiCarvesPath)+"/{env}/{action}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.CarvesActionHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: users
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath)+"/{username}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.UserHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiUsersPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.UsersHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiUsersPath)+"/{username}/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.UserActionHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: platforms
	muxAPI.Handle(
		"GET "+_apiPath(apiPlatformsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.PlatformsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiPlatformsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.PlatformsEnvHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: environments
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/map/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentMapHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/{env}/enroll/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvEnrollActionsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvironmentHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiEnvironmentsPath)+"/{env}/remove/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.EnvRemoveActionsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: tags by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.AllTagsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath)+"/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagsEnvHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiTagsPath)+"/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagEnvHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"POST "+_apiPath(apiTagsPath)+"/{env}/{action}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.TagsActionHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	// API: settings by environment
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath),
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/json",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceJSONHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))
	muxAPI.Handle(
		"GET "+_apiPath(apiSettingsPath)+"/{service}/json/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersApi.SettingsServiceEnvJSONHandler), flagParams.ConfigValues.Auth, flagParams.JWTConfigValues.JWTSecret))

	// Launch listeners for API server
	serviceListener := flagParams.ConfigValues.Listener + ":" + flagParams.ConfigValues.Port
	if flagParams.TLSServer {
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
		if err := srv.ListenAndServeTLS(flagParams.TLSCertFile, flagParams.TLSKeyFile); err != nil {
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
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if flagParams.ConfigFlag {
		flagParams.ConfigValues, err = loadConfiguration(flagParams.ServiceConfigFile, config.ServiceAPI)
		if err != nil {
			return fmt.Errorf("failed to load service configuration %s - %s", flagParams.ServiceConfigFile, err.Error())
		}
	}
	// Load DB configuration if external JSON config file is used
	if flagParams.DBFlag {
		flagParams.DBConfigValues, err = backend.LoadConfiguration(flagParams.DBConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("failed to load DB configuration - %s", err.Error())
		}
	}
	// Load redis configuration if external JSON config file is used
	if flagParams.RedisFlag {
		flagParams.RedisConfigValues, err = cache.LoadConfiguration(flagParams.RedisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("failed to load redis configuration - %s", err.Error())
		}
	}
	// Load JWT configuration if external JWT JSON config file is used
	if flagParams.JWTFlag {
		flagParams.JWTConfigValues, err = loadJWTConfiguration(flagParams.JWTConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load JWT configuration - %s", err.Error())
		}
	}
	return nil
}

func initializeLoggers(cfg config.JSONConfigurationService) {
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
	app = cli.NewApp()
	app.Name = serviceName
	app.Usage = appDescription
	app.Version = buildVersion
	app.Description = appDescription
	app.Flags = flags
	// Customize version output (supports `--version` and `version` command)
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("%s version=%s commit=%s date=%s\n", serviceName, buildVersion, buildCommit, buildDate)
	}
	// Add -v alias to the global --version flag
	cli.VersionFlag = &cli.BoolFlag{
		Name:    "version",
		Aliases: []string{"v"},
		Usage:   "Print version information",
	}
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
	// Start service only for default action; version/help won't trigger this
	app.Action = func(c *cli.Context) error {
		if err := cliAction(c); err != nil {
			return err
		}
		// Initialize service logger
		initializeLoggers(flagParams.ConfigValues)
		// Run the service
		osctrlAPIService()
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Printf("app.Run error: %s", err.Error())
		os.Exit(1)
	}
}
