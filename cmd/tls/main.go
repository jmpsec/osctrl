package main

import (
	"log"
	"net/http"

	"github.com/javuto/osctrl/pkg/carves"
	"github.com/javuto/osctrl/pkg/configuration"
	"github.com/javuto/osctrl/pkg/context"
	"github.com/javuto/osctrl/pkg/metrics"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

// Define endpoints
const (
	// Project name
	projectName = "osctrl"
	// Service name
	serviceName = projectName + "-tls"
	// Service version
	serviceVersion = "0.0.1"
	// Default endpoint to handle HTTP testing
	testingPath = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath = "/error"
	// Service configuration file
	configurationFile = "config/tls.json"
)

// Types of log types
const (
	statusLog = "status"
	resultLog = "result"
	queryLog  = "query"
)

// Global variables
var (
	tlsConfig  JSONConfigurationTLS
	db         *gorm.DB
	config     *configuration.Configuration
	ctxs       *context.Context
	nodesmgr   *nodes.NodeManager
	queriesmgr *queries.Queries
	filecarves *carves.Carves
	_metrics   *metrics.Metrics
	dbConfig   JSONConfigurationDB
	logConfig  JSONConfigurationLogging
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
	tlsRaw := viper.Sub("tls")
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
	// Initialize configuration
	config = configuration.NewConfiguration(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Initialize carves
	filecarves = carves.CreateFileCarves(db)
	// Check if service configuration for debug HTTP is ready
	if !config.IsValue(serviceName, configuration.FieldDebugHTTP) {
		if err := config.NewBooleanValue(serviceName, configuration.FieldDebugHTTP, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", configuration.FieldDebugHTTP, err)
		}
	}
	// Check if service configuration for metrics is ready
	if !config.IsValue(serviceName, configuration.ServiceMetrics) {
		if err := config.NewBooleanValue(serviceName, configuration.ServiceMetrics, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", configuration.ServiceMetrics, err)
		}
	} else if config.ServiceMetrics(serviceName) {
		// Initialize metrics if enabled
		mProtocol, err := config.GetString(serviceName, configuration.MetricsProtocol)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (protocol): %v", err)
		}
		mHost, err := config.GetString(serviceName, configuration.MetricsHost)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (host): %v", err)
		}
		mPort, err := config.GetInteger(serviceName, configuration.MetricsPort)
		if err != nil {
			log.Fatalf("Failed to initialize metrics (port): %v", err)
		}
		_metrics, err = metrics.CreateMetrics(mProtocol, mHost, int(mPort), serviceName)
		if err != nil {
			log.Fatalf("Failed to initialize metrics: %v", err)
		}
	}
	// multiple listeners channel
	finish := make(chan bool)

	/////////////////////////// ALL CONTENT IS UNAUTHENTICATED FOR TLS

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

	// Launch HTTP server for TLS endpoint
	go func() {
		serviceTLS := tlsConfig.Listener + ":" + tlsConfig.Port
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceTLS)
		log.Fatal(http.ListenAndServe(serviceTLS, routerTLS))
	}()

	<-finish
}
