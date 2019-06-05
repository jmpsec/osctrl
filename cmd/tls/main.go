package main

import (
	"log"
	"net/http"
	"time"

	"github.com/javuto/osctrl/pkg/carves"
	"github.com/javuto/osctrl/pkg/context"
	"github.com/javuto/osctrl/pkg/metrics"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

// Define endpoints
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceTLS
	// Service version
	serviceVersion string = "0.0.1"
	// Default endpoint to handle HTTP testing
	testingPath string = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Service configuration file
	configurationFile string = "config/" + settings.ServiceTLS + ".json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
)

// Types of log types
const (
	statusLog string = "status"
	resultLog string = "result"
	queryLog  string = "query"
)

// Global variables
var (
	tlsConfig      JSONConfigurationTLS
	db             *gorm.DB
	settingsmgr    *settings.Settings
	ctxs           *context.Context
	contexts       context.MapContext
	contextTicker  *time.Ticker
	settingsmap    settings.MapSettings
	settingsTicker *time.Ticker
	nodesmgr       *nodes.NodeManager
	queriesmgr     *queries.Queries
	filecarves     *carves.Carves
	_metrics       *metrics.Metrics
	dbConfig       JSONConfigurationDB
	logConfig      JSONConfigurationLogging
)

// Function to load the configuration file and assign to variables
func loadConfiguration() error {
	log.Printf("Loading %s", configurationFile)
	// Load file and read config
	viper.SetConfigFile(configurationFile)
	err := viper.ReadInConfig()
	if err != nil {
		return err
	}
	// TLS endpoint values
	tlsRaw := viper.Sub(settings.ServiceTLS)
	err = tlsRaw.Unmarshal(&tlsConfig)
	if err != nil {
		return err
	}
	// Backend values
	dbRaw := viper.Sub("db")
	err = dbRaw.Unmarshal(&dbConfig)
	if err != nil {
		return err
	}
	// Logging values
	loggingRaw := viper.Sub("logging")
	err = loggingRaw.Unmarshal(&logConfig)
	if err != nil {
		return err
	}
	// No errors!
	return nil
}

// Initialization code
func init() {
	// Logging flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Load configuration
	err := loadConfiguration()
	if err != nil {
		log.Fatalf("Error loading configuration %s", err)
	}
}

// Go go!
func main() {
	log.Println("Loading DB")
	// Database handler
	db = getDB()
	// Close when exit
	//defer db.Close()
	defer func() {
		err := db.Close()
		if err != nil {
			log.Fatalf("Failed to close Database handler %v", err)
		}
	}()
	// Automigrate tables
	if err := automigrateDB(); err != nil {
		log.Fatalf("Failed to AutoMigrate: %v", err)
	}
	// Initialize context
	ctxs = context.CreateContexts(db)
	// Initialize settings
	settingsmgr = settings.NewSettings(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Initialize carves
	filecarves = carves.CreateFileCarves(db)
	log.Println("Loading service settings")
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.DebugService) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceTLS, settings.DebugService, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for metrics is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceTLS, settings.ServiceMetrics, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.ServiceMetrics, err)
		}
	} else if settingsmgr.ServiceMetrics(settings.ServiceTLS) {
		// Initialize metrics if enabled
		mProtocol, err := settingsmgr.GetString(settings.ServiceTLS, settings.MetricsProtocol)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (protocol): %v", err)
		}
		mHost, err := settingsmgr.GetString(settings.ServiceTLS, settings.MetricsHost)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (host): %v", err)
		}
		mPort, err := settingsmgr.GetInteger(settings.ServiceTLS, settings.MetricsPort)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (port): %v", err)
		}
		_metrics, err = metrics.CreateMetrics(mProtocol, mHost, int(mPort), settings.ServiceTLS)
		if err != nil {
			log.Fatalf("Failed to initialize metrics: %v", err)
		}
	}
	// Check if service settings for contexts refresh is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.RefreshContexts) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshContexts, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshContexts, err)
		}
	}
	// Check if service settings for settings refresh is ready
	if !settingsmgr.IsValue(settings.ServiceTLS, settings.RefreshSettings) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceTLS, settings.RefreshSettings, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.RefreshSettings, err)
		}
	}
	// multiple listeners channel
	finish := make(chan bool)

	/////////////////////////// ALL CONTENT IS UNAUTHENTICATED FOR TLS

	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Creating router")
	}

	// Create router for TLS endpoint
	routerTLS := mux.NewRouter()
	// TLS: root
	routerTLS.HandleFunc("/", okHTTPHandler)
	// TLS: testing
	routerTLS.HandleFunc(testingPath, testingHTTPHandler).Methods("GET")
	// TLS: error
	routerTLS.HandleFunc(errorPath, errorHTTPHandler).Methods("GET")
	// TLS: Specific routes for osquery nodes
	// FIXME this forces all paths to be the same
	routerTLS.HandleFunc("/{context}/"+context.DefaultEnrollPath, enrollHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultConfigPath, configHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultLogPath, logHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultQueryReadPath, queryReadHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultQueryWritePath, queryWriteHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultCarverInitPath, carveInitHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+context.DefaultCarverBlockPath, carveBlockHandler).Methods("POST")
	// TLS: Quick enroll/remove script
	routerTLS.HandleFunc("/{context}/{secretpath}/{script}", quickEnrollHandler).Methods("GET")

	// FIXME Redis cache - Ticker to reload contexts
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Contexts ticker")
	}
	go func() {
		_t := settingsmgr.RefreshContexts(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		contextTicker = time.NewTicker(time.Duration(_t) * time.Second)
		for {
			select {
			case <-contextTicker.C:
				go refreshContexts()
			}
		}
	}()

	// FIXME - Ticker to reload settings
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Settings ticker")
	}
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		settingsTicker = time.NewTicker(time.Duration(_t) * time.Second)
		for {
			select {
			case <-settingsTicker.C:
				go refreshSettings()
			}
		}
	}()

	// Launch HTTP server for TLS endpoint
	go func() {
		serviceListener := tlsConfig.Listener + ":" + tlsConfig.Port
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerTLS))
	}()

	<-finish
}
