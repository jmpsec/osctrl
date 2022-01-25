package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmpsec/osctrl/backend"
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
	"github.com/urfave/cli/v2"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAPI
	// Service version
	serviceVersion string = version.OsctrlVersion
	// Service description
	serviceDescription string = "API service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default service configuration file
	defConfigurationFile string = "config/" + settings.ServiceAPI + ".json"
	// Default DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Default JWT configuration file
	defJWTConfigurationFile string = "config/jwt.json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
)

// Paths
const (
	// HTTP health path
	healthPath string = "/health"
	// HTTP errors path
	errorPath     string = "/error"
	forbiddenPath string = "/forbidden"
	// API prefix path
	apiPrefixPath string = "/api"
	// API version path
	apiVersionPath string = "/v1"
	// API nodes path
	apiNodesPath string = "/nodes"
	// API queries path
	apiQueriesPath string = "/queries"
	// API all queries path
	apiAllQueriesPath string = "/all-queries"
	// API carves path
	apiCarvesPath string = "/carves"
	// API platforms path
	apiPlatformsPath string = "/platforms"
	// API environments path
	apiEnvironmentsPath string = "/environments"
	// API tags path
	apiTagsPath string = "/tags"
)

var (
	// Wait for backend in seconds
	backendWait = 7 * time.Second
)

// Global variables
var (
	err         error
	apiConfig   types.JSONConfigurationService
	dbConfig    backend.JSONConfigurationDB
	jwtConfig   types.JSONConfigurationJWT
	db          *gorm.DB
	apiUsers    *users.UserManager
	tagsmgr     *tags.TagManager
	settingsmgr *settings.Settings
	envs        *environments.Environment
	envsmap     environments.MapEnvironments
	settingsmap settings.MapSettings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	_metrics    *metrics.Metrics
	app         *cli.App
	flags       []cli.Flag
)

// Variables for flags
var (
	configFlag    bool
	configFile    string
	loggerValue   string
	dbFlag        bool
	dbConfigFile  string
	jwtFlag       bool
	jwtConfigFile string
	tlsServer     bool
	tlsCertFile   string
	tlsKeyFile    string
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	settings.AuthNone: true,
	settings.AuthJWT:  true,
}
var validLogging = map[string]bool{
	settings.LoggingNone: true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file string) (types.JSONConfigurationService, error) {
	var cfg types.JSONConfigurationService
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// TLS endpoint values
	tlsRaw := viper.Sub(settings.ServiceAPI)
	if err := tlsRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method: '%s'", cfg.Auth)
	}
	if !validLogging[cfg.Logger] {
		return cfg, fmt.Errorf("Invalid logging method")
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
			Destination: &dbConfigFile,
		},
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &apiConfig.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9002",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &apiConfig.Port,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &apiConfig.Auth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &apiConfig.Host,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingNone,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGING"},
			Destination: &loggerValue,
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
			Destination: &configFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbConfig.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbConfig.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "postgres",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbConfig.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbConfig.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbConfig.Password,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbConfig.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbConfig.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConfig.ConnMaxLifetime,
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
			Destination: &jwtConfig.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       3,
			Usage:       "Maximum amount of hours for the tokens to expire",
			EnvVars:     []string{"JWT_EXPIRE"},
			Destination: &jwtConfig.HoursToExpire,
		},
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
}

// Go go!
func osctrlAPIService() {
	log.Println("Initializing backend...")
	for {
		db, err = backend.GetDB(dbConfig)
		if db != nil {
			log.Println("Connection to backend successful!")
			break
		}
		log.Println("Backend NOT ready! waiting...")
		time.Sleep(backendWait)
	}
	if err != nil {
		log.Fatalf("Failed to connect to backend - %v", err)
	}
	// Close when exit
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close Database handler - %v", err)
		}
	}()
	log.Println("Initialize users")
	apiUsers = users.CreateUserManager(db, &jwtConfig)
	log.Println("Initialize tags")
	tagsmgr = tags.CreateTagManager(db)
	log.Println("Initialize environment")
	envs = environments.CreateEnvironment(db)
	// Initialize settings
	log.Println("Initialize settings")
	settingsmgr = settings.NewSettings(db)
	log.Println("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db)
	log.Println("Initialize queries")
	queriesmgr = queries.CreateQueries(db)
	log.Println("Initialize carves")
	filecarves = carves.CreateFileCarves(db)
	log.Println("Loading service settings")
	loadingSettings()

	// Ticker to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Environments ticker")
	}
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
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Settings ticker")
	}
	// Refresh settings as soon as the service starts
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

	// ///////////////////////// API
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Creating router")
	}
	// Create router for API endpoint
	routerAPI := mux.NewRouter()
	// API: root
	routerAPI.HandleFunc("/", rootHTTPHandler)
	// API: testing
	routerAPI.HandleFunc(healthPath, healthHTTPHandler).Methods("GET")
	// API: error
	routerAPI.HandleFunc(errorPath, errorHTTPHandler).Methods("GET")
	// API: forbidden
	routerAPI.HandleFunc(forbiddenPath, forbiddenHTTPHandler).Methods("GET")

	// ///////////////////////// AUTHENTICATED
	// API: nodes
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{uuid}", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{uuid}/", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath), handlerAuthCheck(http.HandlerFunc(apiNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiNodesHandler))).Methods("GET")
	// API: queries
	routerAPI.Handle(_apiPath(apiQueriesPath), handlerAuthCheck(http.HandlerFunc(apiHiddenQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiHiddenQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath), handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/results/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/results/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath), handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	// API: platforms
	routerAPI.Handle(_apiPath(apiPlatformsPath), handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiPlatformsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	// API: environments
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{environment}", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{environment}/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath), handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")
	// API: tags
	routerAPI.Handle(_apiPath(apiTagsPath), handlerAuthCheck(http.HandlerFunc(apiTagsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiTagsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiTagsHandler))).Methods("GET")

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
			Handler:      routerAPI,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Printf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
	} else {
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerAPI))
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external service JSON config file is used
	if configFlag {
		apiConfig, err = loadConfiguration(configFile)
		if err != nil {
			return fmt.Errorf("Failed to load service configuration %s - %s", configFile, err)
		}
	}
	// Load DB configuration if external db JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
		}
	}
	// Load JWT configuration if external JWT JSON config file is used
	if jwtFlag {
		jwtConfig, err = loadJWTConfiguration(jwtConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load JWT configuration - %v", err)
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
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	// Service starts!
	osctrlAPIService()
}
