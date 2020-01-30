package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/metrics"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"

	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAPI
	// Service version
	serviceVersion string = "0.1.9"
	// Service description
	serviceDescription string = "API service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default service configuration file
	configurationFile string = "config/" + settings.ServiceAPI + ".json"
	// Default DB configuration file
	dbConfigurationFile string = "config/db.json"
	// Default JWT configuration file
	jwtConfigurationFile string = "config/jwt.json"
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
)

// Global variables
var (
	apiConfig      types.JSONConfigurationService
	jwtConfig      types.JSONConfigurationJWT
	db             *gorm.DB
	apiUsers       *users.UserManager
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
	jwtFlag     *string
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
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// TLS endpoint values
	tlsRaw := viper.Sub(settings.ServiceAPI)
	err = tlsRaw.Unmarshal(&cfg)
	if err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method: '%s'", cfg.Auth)
	}
	if !validLogging[cfg.Logging] {
		return cfg, fmt.Errorf("Invalid logging method: '%s'", cfg.Logging)
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	var err error
	// Command line flags
	flag.Usage = apiUsage
	// Define flags
	versionFlag = flag.Bool("v", false, "Displays the binary version.")
	configFlag = flag.String("c", configurationFile, "Service configuration JSON file to use.")
	dbFlag = flag.String("D", dbConfigurationFile, "DB configuration JSON file to use.")
	jwtFlag = flag.String("J", jwtConfigurationFile, "JWT configuration JSON file to use.")
	// Parse all flags
	flag.Parse()
	if *versionFlag {
		apiVersion()
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
	// Load API configuration
	apiConfig, err = loadConfiguration(*configFlag)
	if err != nil {
		log.Fatalf("Error loading %s - %s", *configFlag, err)
	}
	// Load JWT configuration
	// Load configuration for JWT if enabled
	if apiConfig.Auth == settings.AuthJWT {
		jwtConfig, err = loadJWTConfiguration(*jwtFlag)
		if err != nil {
			log.Fatalf("Error loading %s - %s", *jwtFlag, err)
		}
		return
	}
}

// Go go!
func main() {
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
	// Initialize users
	apiUsers = users.CreateUserManager(db)
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

	/////////////////////////// API
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

	/////////////////////////// AUTHENTICATED
	// API: nodes
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{uuid}", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{uuid}/", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath), handlerAuthCheck(http.HandlerFunc(apiNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiNodesHandler))).Methods("GET")
	// API: queries
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath), handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath), handlerAuthCheck(http.HandlerFunc(apiHiddenQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiHiddenQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/results/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/results/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath), handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath)+"/", handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	// API: platforms
	routerAPI.Handle(_apiPath(apiPlatformsPath), handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiPlatformsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	// API: environments
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{name}", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{name}/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath), handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")

	// Ticker to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Environments ticker")
	}
	// Refresh environments as soon as service starts
	go refreshEnvironments()
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceAPI)
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
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Settings ticker")
	}
	// Refresh settings as soon as the service starts
	go refreshSettings()
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceAPI)
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
		serviceListener := apiConfig.Listener + ":" + apiConfig.Port
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerAPI))
	}()

	<-finish
}
