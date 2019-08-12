package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceTLS
	// Service version
	serviceVersion string = "0.1.5"
	// Service description
	serviceDescription string = "TLS service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default endpoint to handle HTTP testing
	testingPath string = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Default service configuration file
	configurationFile string = "config/" + settings.ServiceTLS + ".json"
	// Default DB configuration file
	dbConfigurationFile string = "config/db.json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
)

// Global variables
var (
	tlsConfig      types.JSONConfigurationService
	db             *gorm.DB
	settingsmgr    *settings.Settings
	envs           *environments.Environment
	envsmap        environments.MapEnvironments
	envsTicker     *time.Ticker
	settingsmap    settings.MapSettings
	settingsTicker *time.Ticker
	nodesmgr       *nodes.NodeManager
	queriesmgr     *queries.Queries
	filecarves     *carves.Carves
	_metrics       *metrics.Metrics
)

// Variables for flags
var (
	versionFlag *bool
	configFlag  *string
	dbFlag      *string
)

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
	// No errors!
	return cfg, nil
}

// Usage for service binary
func tlsUsage() {
	fmt.Printf("NAME:\n   %s - %s\n\n", serviceName, serviceDescription)
	fmt.Printf("USAGE: %s [global options] [arguments...]\n\n", serviceName)
	fmt.Printf("VERSION:\n   %s\n\n", serviceVersion)
	fmt.Printf("DESCRIPTION:\n   %s\n\n", appDescription)
	fmt.Printf("GLOBAL OPTIONS:\n")
	flag.PrintDefaults()
	fmt.Printf("\n")
}

// Display binary version
func tlsVersion() {
	fmt.Printf("%s v%s\n", serviceName, serviceVersion)
	os.Exit(0)
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

// Loading plugins
func loadPlugins() error {
	log.Println("Loading logging dispatcher plugin")
	if err := loadLoggingDispatcherPlugin(); err != nil {
		return err
	}
	return nil
}

// Go go!
func main() {
	if err := loadPlugins(); err != nil {
		log.Printf("Error loading plugins - %v", err)
	}
	log.Println("Loading DB")
	// Database handler
	db = getDB(*dbFlag)
	// Close when exit
	//defer db.Close()
	defer func() {
		err := db.Close()
		if err != nil {
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
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultEnrollPath, enrollHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultConfigPath, configHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultLogPath, logHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultQueryReadPath, queryReadHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultQueryWritePath, queryWriteHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultCarverInitPath, carveInitHandler).Methods("POST")
	routerTLS.HandleFunc("/{environment}/"+environments.DefaultCarverBlockPath, carveBlockHandler).Methods("POST")
	// TLS: Quick enroll/remove script
	routerTLS.HandleFunc("/{environment}/{secretpath}/{script}", quickEnrollHandler).Methods("GET")

	// Ticker to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService:  Environments ticker")
	}
	// Refresh environments as soon as service starts
	go refreshEnvironments()
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceTLS)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		envsTicker = time.NewTicker(time.Duration(_t) * time.Second)
		for {
			select {
			case <-envsTicker.C:
				go refreshEnvironments()
			}
		}
	}()

	// Ticker to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceTLS) {
		log.Println("DebugService: Settings ticker")
	}
	// Refresh settings as soon as the service starts
	go refreshSettings()
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
