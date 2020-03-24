package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tls/handlers"
	"github.com/jmpsec/osctrl/types"

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
	serviceVersion string = "0.2.1"
	// Service description
	serviceDescription string = "TLS service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Default service configuration file
	configurationFile string = "config/" + settings.ServiceTLS + ".json"
	// Default DB configuration file
	dbConfigurationFile string = "config/db.json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default accelerate interval in seconds
	defaultAccelerate int = 300
	// Default value for keeping maps updated in handlers
	defaultMapRefresh int = 60
)

var (
	// Wait for backend in seconds
	backendWait = 7 * time.Second
)

// Global variables
var (
	tlsConfig   types.JSONConfigurationService
	db          *gorm.DB
	settingsmgr *settings.Settings
	envs        *environments.Environment
	envsmap     environments.MapEnvironments
	settingsmap settings.MapSettings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	_metrics    *metrics.Metrics
	loggerTLS   *logging.LoggerTLS
	handlersTLS *handlers.HandlersTLS
)

// Variables for flags
var (
	versionFlag *bool
	configFlag  *string
	dbFlag      *string
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
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// TLS endpoint values
	tlsRaw := viper.Sub(settings.ServiceTLS)
	err = tlsRaw.Unmarshal(&cfg)
	if err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	if !validLogging[cfg.Logging] {
		return cfg, fmt.Errorf("Invalid logging method")
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	var err error
	// Command line flags
	flag.Usage = tlsUsage
	// Define flags
	versionFlag = flag.Bool("v", false, "Displays the binary version.")
	configFlag = flag.String("c", configurationFile, "Service configuration JSON file to use.")
	dbFlag = flag.String("D", dbConfigurationFile, "DB configuration JSON file to use.")
	// Parse all flags
	flag.Parse()
	if *versionFlag {
		tlsVersion()
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
	// Load TLS configuration
	tlsConfig, err = loadConfiguration(*configFlag)
	if err != nil {
		log.Fatalf("Error loading %s - %s", *configFlag, err)
	}
}

// Go go!
func main() {
	// Backend configuration
	dbConfig, err := backend.LoadConfiguration(*dbFlag, backend.DBKey)
	if err != nil {
		log.Fatalf("Failed to load DB configuration - %v", err)
	}
	// Connect to backend waiting until is ready
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
	//defer db.Close()
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close Database handler - %v", err)
		}
	}()
	// Initialize environment
	envs = environments.CreateEnvironment(db)
	// Initialize settings
	settingsmgr = settings.NewSettings(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Initialize carves
	filecarves = carves.CreateFileCarves(db)
	// Initialize service settings
	log.Println("Loading service settings")
	loadingSettings()
	// Initialize TLS logger
	log.Println("Loading TLS logger")
	loggerTLS, err = logging.CreateLoggerTLS(tlsConfig.Logging, settingsmgr, nodesmgr, queriesmgr)
	if err != nil {
		log.Printf("Error loading logger - %s: %v", tlsConfig.Logging, err)
	}

	// Sleep to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Environments refresher")
	}
	// Refresh environments as soon as service starts
	go refreshEnvironments()
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			time.Sleep(time.Duration(_t) * time.Second)
			go refreshEnvironments()
		}
	}()

	// Sleep to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Settings refresher")
	}
	// Refresh settings as soon as the service starts
	go refreshSettings()
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			time.Sleep(time.Duration(_t) * time.Second)
			go refreshSettings()
		}
	}()

	// Initialize TLS handlers before router
	handlersTLS = handlers.CreateHandlersTLS(
		handlers.WithEnvs(envs),
		handlers.WithEnvsMap(envsmap),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(filecarves),
		handlers.WithSettings(settingsmgr),
		handlers.WithSettingsMap(settingsmap),
		handlers.WithMetrics(_metrics),
		handlers.WithLogs(loggerTLS),
	)
	// Keeping maps updated in the handlers
	go func() {
		for {
			time.Sleep(time.Duration(defaultMapRefresh) * time.Second)
			handlersTLS.EnvsMap = envsmap
			handlersTLS.SettingsMap = settingsmap
		}
	}()

	/////////////////////////// ALL CONTENT IS UNAUTHENTICATED FOR TLS
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

	//////////////////////////////// Everything is ready at this point!

	// multiple listeners channel
	finish := make(chan bool)

	// Launch HTTP server for TLS endpoint
	go func() {
		serviceListener := tlsConfig.Listener + ":" + tlsConfig.Port
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerTLS))
	}()

	<-finish
}
