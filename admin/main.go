package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"

	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

// Constants for the service
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAdmin
	// Service version
	serviceVersion string = "0.2.1"
	// Service description
	serviceDescription string = "Admin service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle Login
	loginPath string = "/login"
	// Default endpoint to handle HTTP(500) errors
	errorPath string = "/error"
	// Default endpoint to handle Forbidden(403) errors
	forbiddenPath string = "/forbidden"
	// Default service configuration file
	configurationFile string = "config/" + settings.ServiceAdmin + ".json"
	// Default DB configuration file
	dbConfigurationFile string = "config/db.json"
	// Default SAML configuration file
	samlConfigurationFile string = "config/saml.json"
	// Default JWT configuration file
	jwtConfigurationFile string = "config/jwt.json"
	// Default Headers configuration file
	headersConfigurationFile string = "config/headers.json"
	// osquery version to display tables
	osqueryTablesVersion string = "4.2.0"
	// JSON file with osquery tables data
	osqueryTablesFile string = "data/" + osqueryTablesVersion + ".json"
	// Static files folder
	staticFilesFolder string = "./static"
	// Carved files folder
	carvedFilesFolder string = "carved_files/"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default hours to classify nodes as inactive
	defaultInactive int = -72
)

var (
	// Wait for backend in seconds
	backendWait = 7 * time.Second
)

// Global general variables
var (
	adminConfig    types.JSONConfigurationService
	db             *gorm.DB
	settingsmgr    *settings.Settings
	nodesmgr       *nodes.NodeManager
	queriesmgr     *queries.Queries
	carvesmgr      *carves.Carves
	sessionsmgr    *SessionManager
	envs           *environments.Environment
	adminUsers     *users.UserManager
	sessionsTicker *time.Ticker
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []OsqueryTable
	_metrics      *metrics.Metrics
)

// Variables for flags
var (
	versionFlag *bool
	configFlag  *string
	dbFlag      *string
	samlFlag    *string
	headersFlag *string
	jwtFlag     *string
)

// SAML variables
var (
	samlMiddleware *samlsp.Middleware
	samlConfig     JSONConfigurationSAML
	samlData       samlThings
)

// Headers variables
var (
	headersConfig types.JSONConfigurationHeaders
)

// JWT variables
var (
	jwtConfig types.JSONConfigurationJWT
)

// Valid values for auth in configuration
var validAuth = map[string]bool{
	settings.AuthDB:      true,
	settings.AuthSAML:    true,
	settings.AuthHeaders: true,
	settings.AuthJSON:    true,
}

// Valid values for logging in configuration
var validLogging = map[string]bool{
	settings.LoggingDB:     true,
	settings.LoggingSplunk: true,
}

// Function to load the configuration file
func loadConfiguration(file, service string) (types.JSONConfigurationService, error) {
	var cfg types.JSONConfigurationService
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return cfg, err
	}
	// Admin values
	adminRaw := viper.Sub(service)
	err = adminRaw.Unmarshal(&cfg)
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
	flag.Usage = adminUsage
	// Define flags
	versionFlag = flag.Bool("v", false, "Displays the binary version.")
	configFlag = flag.String("c", configurationFile, "Service configuration JSON file to use.")
	dbFlag = flag.String("D", dbConfigurationFile, "DB configuration JSON file to use.")
	samlFlag = flag.String("S", samlConfigurationFile, "SAML configuration JSON file to use.")
	headersFlag = flag.String("H", headersConfigurationFile, "Headers configuration JSON file to use.")
	jwtFlag = flag.String("J", jwtConfigurationFile, "JWT configuration JSON file to use.")
	// Parse all flags
	flag.Parse()
	if *versionFlag {
		adminVersion()
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
	// Load admin configuration
	adminConfig, err = loadConfiguration(*configFlag, settings.ServiceAdmin)
	if err != nil {
		log.Fatalf("Error loading %s - %s", *configFlag, err)
	}
	// Load osquery tables JSON
	osqueryTables, err = loadOsqueryTables(osqueryTablesFile)
	if err != nil {
		log.Fatalf("Error loading osquery tables %s", err)
	}
	// Load configuration for SAML if enabled
	if adminConfig.Auth == settings.AuthSAML {
		samlConfig, err = loadSAML(*samlFlag)
		if err != nil {
			log.Fatalf("Error loading %s - %s", *samlFlag, err)
		}
	}
	// Load configuration for Headers if enabled
	if adminConfig.Auth == settings.AuthHeaders {
		headersConfig, err = loadHeaders(*headersFlag)
		if err != nil {
			log.Fatalf("Error loading %s - %s", *headersFlag, err)
		}
	}
	// Load JWT configuration
	jwtConfig, err = loadJWTConfiguration(*jwtFlag)
	if err != nil {
		log.Fatalf("Error loading %s - %s", *jwtFlag, err)
	}
}

// Go go!
func main() {
	// Database handler
	dbConfig, err := backend.LoadConfiguration(*dbFlag, backend.DBKey)
	if err != nil {
		log.Fatalf("Failed to load DB configuration - %v", err)
	}
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
	// Automigrate tables
	if err := automigrateDB(); err != nil {
		log.Fatalf("Failed to AutoMigrate: %v", err)
	}
	// Initialize users
	adminUsers = users.CreateUserManager(db)
	// Initialize environment
	envs = environments.CreateEnvironment(db)
	// Initialize settings
	settingsmgr = settings.NewSettings(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Initialize carves
	carvesmgr = carves.CreateFileCarves(db)
	// Initialize sessions
	sessionsmgr = CreateSessionManager(db)
	// Initialize service settings
	log.Println("Loading service settings")
	loadingSettings()
	// multiple listeners channel
	finish := make(chan bool)

	// Start SAML Middleware if we are using SAML
	if adminConfig.Auth == settings.AuthSAML {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: SAML keypair")
		}
		// Initialize SAML keypair to sign SAML Request.
		var err error
		samlData, err = keypairSAML(samlConfig)
		if err != nil {
			log.Fatalf("Can not initialize SAML keypair %s", err)
		}
		samlMiddleware, err = samlsp.New(samlsp.Options{
			URL:               *samlData.RootURL,
			Key:               samlData.KeyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       samlData.KeyPair.Leaf,
			IDPMetadataURL:    samlData.IdpMetadataURL,
			AllowIDPInitiated: true,
		})
		if err != nil {
			log.Fatalf("Can not initialize SAML Middleware %s", err)
		}
	}

	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Creating router")
	}

	// Create router for admin
	routerAdmin := mux.NewRouter()

	/////////////////////////// UNAUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Unauthenticated content")
	}

	// Admin: login only if local auth is enabled
	if adminConfig.Auth != settings.AuthNone {
		// login
		routerAdmin.HandleFunc(loginPath, loginGETHandler).Methods("GET")
		routerAdmin.HandleFunc(loginPath, loginPOSTHandler).Methods("POST")
	}
	// Admin: health of service
	routerAdmin.HandleFunc(healthPath, healthHTTPHandler).Methods("GET")
	// Admin: error
	routerAdmin.HandleFunc(errorPath, errorHTTPHandler).Methods("GET")
	// Admin: forbidden
	routerAdmin.HandleFunc(forbiddenPath, forbiddenHTTPHandler).Methods("GET")
	// Admin: favicon
	routerAdmin.HandleFunc("/favicon.ico", faviconHandler)
	// Admin: static
	routerAdmin.PathPrefix("/static/").Handler(
		http.StripPrefix("/static", http.FileServer(http.Dir(staticFilesFolder))))

	/////////////////////////// AUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Authenticated content")
	}

	// Admin: JSON data for environments
	routerAdmin.Handle("/json/environment/{environment}/{target}", handlerAuthCheck(http.HandlerFunc(jsonEnvironmentHandler))).Methods("GET")
	// Admin: JSON data for platforms
	routerAdmin.Handle("/json/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(jsonPlatformHandler))).Methods("GET")
	// Admin: JSON data for logs
	routerAdmin.Handle("/json/logs/{type}/{environment}/{uuid}", handlerAuthCheck(http.HandlerFunc(jsonLogsHandler))).Methods("GET")
	// Admin: JSON data for query logs
	routerAdmin.Handle("/json/query/{name}", handlerAuthCheck(http.HandlerFunc(jsonQueryLogsHandler))).Methods("GET")
	// Admin: JSON data for sidebar stats
	routerAdmin.Handle("/json/stats/{target}/{name}", handlerAuthCheck(http.HandlerFunc(jsonStatsHandler))).Methods("GET")
	// Admin: table for environments
	routerAdmin.Handle("/environment/{environment}/{target}", handlerAuthCheck(http.HandlerFunc(environmentHandler))).Methods("GET")
	// Admin: table for platforms
	routerAdmin.Handle("/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(platformHandler))).Methods("GET")
	// Admin: dashboard
	//routerAdmin.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	routerAdmin.Handle("/dashboard", handlerAuthCheck(http.HandlerFunc(rootHandler))).Methods("GET")
	// Admin: root
	routerAdmin.Handle("/", handlerAuthCheck(http.HandlerFunc(rootHandler))).Methods("GET")
	// Admin: node view
	routerAdmin.Handle("/node/{uuid}", handlerAuthCheck(http.HandlerFunc(nodeHandler))).Methods("GET")
	// Admin: multi node action
	routerAdmin.Handle("/node/actions", handlerAuthCheck(http.HandlerFunc(nodeActionsPOSTHandler))).Methods("POST")
	// Admin: run queries
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(queryRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(queryRunPOSTHandler))).Methods("POST")
	// Admin: list queries
	routerAdmin.Handle("/query/list", handlerAuthCheck(http.HandlerFunc(queryListGETHandler))).Methods("GET")
	// Admin: query actions
	routerAdmin.Handle("/query/actions", handlerAuthCheck(http.HandlerFunc(queryActionsPOSTHandler))).Methods("POST")
	// Admin: query JSON
	routerAdmin.Handle("/query/json/{target}", handlerAuthCheck(http.HandlerFunc(jsonQueryHandler))).Methods("GET")
	// Admin: query logs
	routerAdmin.Handle("/query/logs/{name}", handlerAuthCheck(http.HandlerFunc(queryLogsHandler))).Methods("GET")
	// Admin: carve files
	routerAdmin.Handle("/carves/run", handlerAuthCheck(http.HandlerFunc(carvesRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/carves/run", handlerAuthCheck(http.HandlerFunc(carvesRunPOSTHandler))).Methods("POST")
	// Admin: list carves
	routerAdmin.Handle("/carves/list", handlerAuthCheck(http.HandlerFunc(carvesListGETHandler))).Methods("GET")
	// Admin: carves actions
	routerAdmin.Handle("/carves/actions", handlerAuthCheck(http.HandlerFunc(carvesActionsPOSTHandler))).Methods("POST")
	// Admin: carves JSON
	routerAdmin.Handle("/carves/json/{target}", handlerAuthCheck(http.HandlerFunc(jsonCarvesHandler))).Methods("GET")
	// Admin: carves details
	routerAdmin.Handle("/carves/details/{name}", handlerAuthCheck(http.HandlerFunc(carvesDetailsHandler))).Methods("GET")
	// Admin: carves download
	routerAdmin.Handle("/carves/download/{sessionid}", handlerAuthCheck(http.HandlerFunc(carvesDownloadHandler))).Methods("GET")
	// Admin: nodes configuration
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(confGETHandler))).Methods("GET")
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(confPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/intervals/{environment}", handlerAuthCheck(http.HandlerFunc(intervalsPOSTHandler))).Methods("POST")
	// Admin: nodes enroll
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(enrollGETHandler))).Methods("GET")
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(enrollPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/expiration/{environment}", handlerAuthCheck(http.HandlerFunc(expirationPOSTHandler))).Methods("POST")
	// Admin: server settings
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(settingsGETHandler))).Methods("GET")
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(settingsPOSTHandler))).Methods("POST")
	// Admin: manage environments
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(envsGETHandler))).Methods("GET")
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(envsPOSTHandler))).Methods("POST")
	// Admin: manage users
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(usersGETHandler))).Methods("GET")
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(usersPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(permissionsGETHandler))).Methods("GET")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(permissionsPOSTHandler))).Methods("POST")
	// Admin: manage tokens
	routerAdmin.Handle("/tokens/{username}", handlerAuthCheck(http.HandlerFunc(tokensGETHandler))).Methods("GET")
	routerAdmin.Handle("/tokens/{username}/refresh", handlerAuthCheck(http.HandlerFunc(tokensPOSTHandler))).Methods("POST")
	// logout
	routerAdmin.Handle("/logout", handlerAuthCheck(http.HandlerFunc(logoutPOSTHandler))).Methods("POST")

	// SAML ACS
	if adminConfig.Auth == settings.AuthSAML {
		routerAdmin.PathPrefix("/saml/").Handler(samlMiddleware)
	}

	// FIXME Redis cache - Ticker to cleanup sessions
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Sessions ticker")
	}
	go func() {
		_t := settingsmgr.CleanupSessions()
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		sessionsTicker = time.NewTicker(time.Duration(_t) * time.Second)
		for {
			select {
			case <-sessionsTicker.C:
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Println("DebugService: Cleaning up sessions")
				}
				go sessionsmgr.Cleanup()
			}
		}
	}()

	// Launch HTTP server for admin
	go func() {
		serviceAdmin := adminConfig.Listener + ":" + adminConfig.Port
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}()

	<-finish
}
