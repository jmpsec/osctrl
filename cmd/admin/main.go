package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/users"

	"github.com/crewjam/saml/samlsp"
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
	serviceNameAdmin string = projectName + "-" + settings.ServiceAdmin
	// Service version
	serviceVersion string = "1.0.0"
	// Default endpoint to handle HTTP testing
	testingPath string = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath string = "/error"
	// Service configuration file
	configurationFile string = "config/admin.json"
	// osquery version to display tables
	osqueryTablesVersion string = "3.3.2"
	// JSON file with osquery tables data
	osqueryTablesFile string = "data/" + osqueryTablesVersion + ".json"
	// Static files folder
	staticFilesFolder string = "./static"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default hours to classify nodes as inactive
	defaultInactive int = -72
)

// Global variables
var (
	adminConfig    JSONConfigurationService
	samlMiddleware *samlsp.Middleware
	samlConfig     JSONConfigurationSAML
	db             *gorm.DB
	settingsmgr    *settings.Settings
	nodesmgr       *nodes.NodeManager
	queriesmgr     *queries.Queries
	sessionsmgr    *SessionManager
	envs           *environments.Environment
	adminUsers     *users.UserManager
	sessionsTicker *time.Ticker
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
	// TLS Admin values
	adminRaw := viper.Sub("admin")
	err = adminRaw.Unmarshal(&adminConfig)
	if err != nil {
		return err
	}
	// Load configuration for the auth method
	if adminConfig.Auth == settings.AuthSAML {
		samlRaw := viper.Sub(settings.AuthSAML)
		err = samlRaw.Unmarshal(&samlConfig)
		if err != nil {
			return err
		}
	}
	// No errors!
	return nil
}

// Function to load the JSON data for osquery tables
func loadOsqueryTables() error {
	jsonFile, err := os.Open(osqueryTablesFile)
	if err != nil {
		return err
	}
	//defer jsonFile.Close()
	defer func() {
		err := jsonFile.Close()
		if err != nil {
			log.Fatalf("Failed to close tables file %v", err)
		}
	}()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &osqueryTables)
	if err != nil {
		return err
	}
	// Add a string for platforms to be used as filter
	for i, t := range osqueryTables {
		filter := ""
		for _, p := range t.Platforms {
			filter += " filter-" + p
		}
		osqueryTables[i].Filter = strings.TrimSpace(filter)
	}
	return nil
}

// Initialization code
func init() {
	// Logging flags
	log.SetFlags(log.Lshortfile)
	// Load configuration
	if err := loadConfiguration(); err != nil {
		log.Fatalf("Error loading configuration %s", err)
	}
	// Load osquery tables JSON
	if err := loadOsqueryTables(); err != nil {
		log.Fatalf("Error loading osquery tables %s", err)
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
	// Initialize sessions
	sessionsmgr = CreateSessionManager(db)
	log.Println("Loading service settings")
	// Check if service settings for debug service is ready
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Initializing settings")
	}
	// Check if service settings for debug service is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DebugService) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugService, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugService, err)
		}
	}
	// Check if service settings for debug HTTP is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DebugHTTP) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.DebugHTTP, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	}
	// Check if service settings for metrics is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.ServiceMetrics) {
		if err := settingsmgr.NewBooleanValue(settings.ServiceAdmin, settings.ServiceMetrics, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.ServiceMetrics, err)
		}
	}
	// Check if service settings for default environment is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.DefaultEnv) {
		if err := settingsmgr.NewStringValue(settings.ServiceAdmin, settings.DefaultEnv, "dev"); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DefaultEnv, err)
		}
	}
	// Check if service settings for sessions cleanup is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.CleanupSessions) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanupSessions, int64(defaultRefresh)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.CleanupSessions, err)
		}
	}
	// Check if service settings for node inactive hours is ready
	if !settingsmgr.IsValue(settings.ServiceAdmin, settings.InactiveHours) {
		if err := settingsmgr.NewIntegerValue(settings.ServiceAdmin, settings.InactiveHours, int64(defaultInactive)); err != nil {
			log.Fatalf("Failed to add %s to configuration: %v", settings.InactiveHours, err)
		}
	}
	// multiple listeners channel
	finish := make(chan bool)
	// Start SAML Middleware if we are using SAML
	if adminConfig.Auth == settings.AuthSAML {
		if settingsmgr.DebugService(settings.ServiceAdmin) {
			log.Println("DebugService: SAML keypair")
		}
		// Load Keypair to Sign SAML Request.
		var err error
		var rootURL *url.URL
		var idpMetadataURL *url.URL
		var keyPair tls.Certificate
		keyPair, err = tls.LoadX509KeyPair(samlConfig.CertPath, samlConfig.KeyPath)
		if err != nil {
			log.Fatal(err)
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
		idpMetadataURL, err = url.Parse(samlConfig.MetaDataURL)
		if err != nil {
			log.Fatal(err)
		}
		rootURL, err = url.Parse(samlConfig.RootURL)
		if err != nil {
			log.Fatal(err)
		}
		samlMiddleware, err = samlsp.New(samlsp.Options{
			URL:               *rootURL,
			Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       keyPair.Leaf,
			IDPMetadataURL:    idpMetadataURL,
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
		routerAdmin.HandleFunc("/login", loginGETHandler).Methods("GET")
		routerAdmin.HandleFunc("/login", loginPOSTHandler).Methods("POST")
	}
	// Admin: testing
	routerAdmin.HandleFunc(testingPath, testingHTTPHandler).Methods("GET")
	// Admin: error
	routerAdmin.HandleFunc(errorPath, errorHTTPHandler).Methods("GET")
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
	// Admin: single node action
	routerAdmin.Handle("/action/{uuid}", handlerAuthCheck(http.HandlerFunc(nodeActionHandler))).Methods("POST")
	// Admin: multi node action
	routerAdmin.Handle("/actions", handlerAuthCheck(http.HandlerFunc(nodeMultiActionHandler))).Methods("POST")
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
	// Admin: nodes configuration
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(confGETHandler))).Methods("GET")
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(confPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/intervals/{environment}", handlerAuthCheck(http.HandlerFunc(intervalsPOSTHandler))).Methods("POST")
	// Admin: nodes enroll
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(enrollGETHandler))).Methods("GET")
	routerAdmin.Handle("/expiration/{environment}", handlerAuthCheck(http.HandlerFunc(expirationPOSTHandler))).Methods("POST")
	// Admin: server settings
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(settingsGETHandler))).Methods("GET")
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(settingsPOSTHandler))).Methods("POST")
	// Admin: manage environments
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(envsGETHandler))).Methods("GET")
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(envsPOSTHandler))).Methods("POST")
	// Admin: manage users if authentication is enabled
	if adminConfig.Auth != settings.AuthNone {
		routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(usersGETHandler))).Methods("GET")
		routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(usersPOSTHandler))).Methods("POST")
		// logout
		routerAdmin.Handle("/logout", handlerAuthCheck(http.HandlerFunc(logoutHandler))).Methods("POST")
	}

	// SAML ACS
	if adminConfig.Auth == settings.AuthNone {
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
		log.Printf("%s v%s - HTTP listening %s", serviceNameAdmin, serviceVersion, serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}()

	<-finish
}
