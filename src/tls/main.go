package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

// Define endpoints
const (
	// Application name
	appName = "osctrl"
	// Service name
	serviceName = appName + "-tls"
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
	tlsConfig    JSONConfigurationTLS
	tlsPath      TLSPath
	db           *gorm.DB
	config       *ServiceConfiguration
	dbConfig     JSONConfigurationDB
	logConfig    JSONConfigurationLogging
	geolocConfig JSONConfigurationGeoLocation
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []OsqueryTable
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
	// TLS paths
	tlsPath = TLSPath{
		EnrollPath:      defaultEnrollPath,
		LogPath:         defaultLogPath,
		ConfigPath:      defaultConfigPath,
		QueryReadPath:   defaultQueryReadPath,
		QueryWritePath:  defaultQueryWritePath,
		CarverInitPath:  defaultCarverInitPath,
		CarverBlockPath: defaultCarverBlockPath,
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
	// GeoLocation values
	geolocRaw := viper.Sub("geolocation")
	err = geolocRaw.Unmarshal(&geolocConfig)
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
	defer db.Close()
	// Automigrate tables
	if err := automigrateDB(); err != nil {
		log.Fatalf("Failed to AutoMigrate: %v", err)
	}
	// Service configuration
	var err error
	config, err = NewServiceConfiguration(db)
	if err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}
	if !config.IsValue(serviceName, DebugHTTP) {
		if err := config.NewBooleanValue(serviceName, DebugHTTP, false); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", DebugHTTP, err)
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
	routerTLS.HandleFunc("/{context}/"+tlsPath.EnrollPath, enrollHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+tlsPath.ConfigPath, configHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+tlsPath.LogPath, logHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+tlsPath.QueryReadPath, queryReadHandler).Methods("POST")
	routerTLS.HandleFunc("/{context}/"+tlsPath.QueryWritePath, queryWriteHandler).Methods("POST")
	// TLS: Quick enrollment script
	routerTLS.HandleFunc("/{context}/{secretpath}/{script}", quickEnrollHandler).Methods("GET")

	// Launch HTTP server for TLS endpoint
	go func() {
		serviceTLS := tlsConfig.Listener + ":" + tlsConfig.Port
		log.Printf("HTTP enroll listening %s", serviceTLS)
		log.Fatal(http.ListenAndServe(serviceTLS, routerTLS))
	}()

	<-finish
}
