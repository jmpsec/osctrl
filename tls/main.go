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
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	thandlers "github.com/jmpsec/osctrl/tls/handlers"
	"github.com/jmpsec/osctrl/types"
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
	// Default TLS certificate file
	defTLSCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile string = "config/tls.key"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default accelerate interval in seconds
	defaultAccelerate int = 300
)

var (
	// Wait for backend in seconds
	backendWait = 7 * time.Second
)

// Global variables
var (
	err         error
	tlsConfig   types.JSONConfigurationService
	dbConfig    backend.JSONConfigurationDB
	db          *gorm.DB
	settingsmgr *settings.Settings
	envs        *environments.Environment
	envsmap     environments.MapEnvironments
	settingsmap settings.MapSettings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	tlsMetrics  *metrics.Metrics
	loggerTLS   *logging.LoggerTLS
	handlersTLS *thandlers.HandlersTLS
	tagsmgr     *tags.TagManager
	app         *cli.App
	flags       []cli.Flag
)

// Variables for flags
var (
	configFlag        bool
	configFile        string
	dbFlag            bool
	dbConfigFile      string
	tlsServer         bool
	tlsCertFile       string
	tlsKeyFile        string
	cfgListener       string
	cfgPort           string
	cfgHost           string
	cfgAuth           string
	cfgLogging        string
	dbHost            string
	dbPort            string
	dbName            string
	dbUsername        string
	dbPassword        string
	dbMaxIdleConns    int
	dbMaxOpenConns    int
	dbConnMaxLifetime int
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	settings.AuthNone: true,
}
var validLogging = map[string]bool{
	settings.LoggingDB:      true,
	settings.LoggingGraylog: true,
	settings.LoggingSplunk:  true,
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
	tlsRaw := viper.Sub(settings.ServiceTLS)
	if err := tlsRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	for _, _l := range cfg.Logging {
		if !validLogging[_l] {
			return cfg, fmt.Errorf("Invalid logging method")
		}
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
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
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &cfgListener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9000",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &cfgPort,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &cfgAuth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &cfgHost,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingDB,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGING"},
			Destination: &cfgLogging,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbHost,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbPort,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "postgres",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbName,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbUsername,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbPassword,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbMaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbMaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConnMaxLifetime,
		},
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
}

// Go go!
func osctrlService() {
	log.Println("Initializing backend...")
	// Attempt to connect to backend waiting until is ready
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
	log.Println("Initialize environment")
	envs = environments.CreateEnvironment(db)
	log.Println("Initialize settings")
	settingsmgr = settings.NewSettings(db)
	log.Println("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db)
	log.Println("Initialize tags")
	tagsmgr = tags.CreateTagManager(db)
	log.Println("Initialize queries")
	queriesmgr = queries.CreateQueries(db)
	log.Println("Initialize carves")
	filecarves = carves.CreateFileCarves(db)
	log.Println("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatalf("Error loading settings - %s: %v", tlsConfig.Logging, err)
	}
	// Initialize metrics
	log.Println("Loading service metrics")
	tlsMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatalf("Error loading metrics - %v", err)
	}
	// Initialize TLS logger
	log.Println("Loading TLS logger")
	loggerTLS, err = logging.CreateLoggerTLS(tlsConfig.Logging, settingsmgr, nodesmgr, queriesmgr)
	if err != nil {
		log.Fatalf("Error loading logger - %s: %v", tlsConfig.Logging, err)
	}

	// Sleep to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Println("Preparing pseudo-cache for environments")
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceTLS) {
				log.Println("DebugService: Refreshing environments")
			}
			envsmap = refreshEnvironments()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	// Sleep to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	log.Println("Preparing pseudo-cache for settings")
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceTLS) {
				log.Println("DebugService: Refreshing settings")
			}
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	// Initialize TLS handlers before router
	handlersTLS = thandlers.CreateHandlersTLS(
		thandlers.WithEnvs(envs),
		thandlers.WithEnvsMap(&envsmap),
		thandlers.WithNodes(nodesmgr),
		thandlers.WithTags(tagsmgr),
		thandlers.WithQueries(queriesmgr),
		thandlers.WithCarves(filecarves),
		thandlers.WithSettings(settingsmgr),
		thandlers.WithSettingsMap(&settingsmap),
		thandlers.WithMetrics(tlsMetrics),
		thandlers.WithLogs(loggerTLS),
	)

	// ///////////////////////// ALL CONTENT IS UNAUTHENTICATED FOR TLS
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Creating router")
	}
	// Create router for TLS endpoint
	routerTLS := mux.NewRouter()
	// TLS: root
	routerTLS.HandleFunc("/", handlersTLS.RootHandler)
	// TLS: testing
	routerTLS.HandleFunc(healthPath, handlersTLS.HealthHandler).Methods("GET")
	// TLS: error
	routerTLS.HandleFunc(errorPath, handlersTLS.ErrorHandler).Methods("GET")
	// TLS: Specific routes for osquery nodes
	// FIXME this forces all paths to be the same
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultEnrollPath, handlersTLS.EnrollHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultConfigPath, handlersTLS.ConfigHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultLogPath, handlersTLS.LogHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultQueryReadPath, handlersTLS.QueryReadHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultQueryWritePath, handlersTLS.QueryWriteHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultCarverInitPath, handlersTLS.CarveInitHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultCarverBlockPath, handlersTLS.CarveBlockHandler).Methods("POST")
	// TLS: Quick enroll/remove script
	routerTLS.HandleFunc("/{environment}/{secretpath}/{script}", handlersTLS.QuickEnrollHandler).Methods("GET")

	// ////////////////////////////// Everything is ready at this point!
	serviceListener := tlsConfig.Listener + ":" + tlsConfig.Port
	if tlsServer {
		log.Println("TLS Termination is enabled")
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
			Handler:      routerTLS,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Printf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
	} else {
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerTLS))
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external service JSON config file is used
	if configFlag {
		tlsConfig, err = loadConfiguration(configFile)
		if err != nil {
			return fmt.Errorf("Error loading %s - %s", configFile, err)
		}
	}
	// Load db configuration if external db JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
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
			Name:            "help",
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
	osctrlService()
}
