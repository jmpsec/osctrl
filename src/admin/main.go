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

	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

// Define endpoints
const (
	// Application name
	appName = "osctrl"
	// Service name
	serviceName = appName + "-admin"
	// Service version
	serviceVersion = "0.0.1"
	// Default endpoint to handle HTTP testing
	testingPath = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath = "/error"
	// Service configuration file
	configurationFile = "config/admin.json"
	// osquery version to display tables
	osqueryTablesVersion = "3.3.0"
	// JSON file with osquery tables data
	osqueryTablesFile = "data/" + osqueryTablesVersion + ".json"
	// No login
	noAuthLogin = "none"
	// Local login
	localAuthLogin = "local"
	// SAML login
	samlAuthLogin = "saml"
)

// Types of log types
const (
	statusLog = "status"
	resultLog = "result"
	queryLog  = "query"
)

// Global variables
var (
	tlsPath        TLSPath
	adminConfig    JSONConfigurationAdmin
	samlMiddleware *samlsp.Middleware
	samlConfig     JSONConfigurationSAML
	db             *gorm.DB
	dbConfig       JSONConfigurationDB
	logConfig      JSONConfigurationLogging
	geolocConfig   JSONConfigurationGeoLocation
	store          *sessions.CookieStore
	storeKey       []byte
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
	// TLS Admin values
	adminRaw := viper.Sub("admin")
	err = adminRaw.Unmarshal(&adminConfig)
	if err != nil {
		return err
	}
	// Load configuration for the auth method
	switch adminConfig.Auth {
	case "saml":
		samlRaw := viper.Sub("saml")
		err = samlRaw.Unmarshal(&samlConfig)
		if err != nil {
			return err
		}
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

// Function to load the JSON data for osquery tables
func loadOsqueryTables() error {
	jsonFile, err := os.Open(osqueryTablesFile)
	if err != nil {
		return err
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	err = json.Unmarshal(byteValue, &osqueryTables)
	if err != nil {
		return err
	}
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
	// Generate cookie store with proper options
	if adminConfig.Auth != noAuthLogin {
		storeKey = securecookie.GenerateRandomKey(32)
		store = sessions.NewCookieStore(storeKey)
		store.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 7,
			Secure:   true,
			HttpOnly: true,
		}
	}
	// Load osquery tables JSON
	err = loadOsqueryTables()
	if err != nil {
		log.Fatalf("Error loading osquery tables %s", err)
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

	// multiple listeners channel
	finish := make(chan bool)

	// Start SAML Middleware if we are using SAML
	if adminConfig.Auth == samlAuthLogin {
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

	/////////////////////////// UNAUTHENTICATED CONTENT

	// Create router for admin
	routerAdmin := mux.NewRouter()
	// Admin: login only if local auth is enabled
	if adminConfig.Auth == localAuthLogin {
		// login
		routerAdmin.HandleFunc("/login", loginGETHandler).Methods("GET")
		routerAdmin.HandleFunc("/login", loginPOSTHandler).Methods("POST")
		// logout
		routerAdmin.HandleFunc("/logout", logoutHandler).Methods("POST")
	}
	// Admin: favicon
	routerAdmin.HandleFunc("/favicon.ico", faviconHandler)
	// Admin: static
	routerAdmin.PathPrefix("/static/").Handler(
		http.StripPrefix("/static", http.FileServer(http.Dir("./static"))))

	/////////////////////////// AUTHENTICATED CONTENT

	// Admin: JSON data for contexts
	routerAdmin.Handle("/json/context/{context}/{target}", handlerAuthCheck(http.HandlerFunc(jsonContextHandler))).Methods("GET")
	// Admin: JSON data for platforms
	routerAdmin.Handle("/json/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(jsonPlatformHandler))).Methods("GET")
	// Admin: JSON data for status logs
	routerAdmin.Handle("/json/status/{context}/{uuid}", handlerAuthCheck(http.HandlerFunc(jsonStatusLogsHandler))).Methods("GET")
	// Admin: JSON data for result logs
	routerAdmin.Handle("/json/result/{context}/{uuid}", handlerAuthCheck(http.HandlerFunc(jsonResultLogsHandler))).Methods("GET")
	// Admin: JSON data for query logs
	routerAdmin.Handle("/json/query/{name}", handlerAuthCheck(http.HandlerFunc(jsonQueryLogsHandler))).Methods("GET")
	// Admin: JSON data for sidebar stats
	routerAdmin.Handle("/json/stats/{target}", handlerAuthCheck(http.HandlerFunc(jsonStatsHandler))).Methods("GET")
	// Admin: table for contexts
	routerAdmin.Handle("/context/{context}/{target}", handlerAuthCheck(http.HandlerFunc(contextHandler))).Methods("GET")
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
	// Admin: queries
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(queryRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(queryRunPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/query/active", handlerAuthCheck(http.HandlerFunc(queryActiveGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/completed", handlerAuthCheck(http.HandlerFunc(queryCompletedGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/actions", handlerAuthCheck(http.HandlerFunc(queryActionsPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/query/json/{target}", handlerAuthCheck(http.HandlerFunc(jsonQueryHandler))).Methods("GET")
	routerAdmin.Handle("/query/logs/{name}", handlerAuthCheck(http.HandlerFunc(queryLogsHandler))).Methods("GET")
	// Admin: nodes configuration
	routerAdmin.Handle("/conf/{context}", handlerAuthCheck(http.HandlerFunc(showConfigHandler))).Methods("GET")
	// Admin: server settings
	//routerAdmin.Handle("/settings/{target}", handlerAuthCheck(http.HandlerFunc(settingsGETHandler))).Methods("GET")
	//routerAdmin.Handle("/settings/{target}", handlerAuthCheck(http.HandlerFunc(settingsPOSTHandler))).Methods("POST")
	// Admin: Packages to enroll
	//routerAdmin.Handle("/package/{context}/{platform}", handlerAuthCheck(http.HandlerFunc(packageHandler))).Methods("GET")
	// SAML ACS
	if adminConfig.Auth == samlAuthLogin {
		routerAdmin.PathPrefix("/saml/").Handler(samlMiddleware)
	}

	// Launch HTTP server for admin
	go func() {
		serviceAdmin := adminConfig.Listener + ":" + adminConfig.Port
		log.Printf("HTTP admin listening %s", serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}()

	<-finish
}
