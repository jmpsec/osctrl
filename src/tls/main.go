package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

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
	serviceName = appName + "-tls"
	// Service version
	serviceVersion = "0.0.1"
	// Default endpoint to handle HTTP testing
	testingPath = "/testing"
	// Default endpoint to handle HTTP errors
	errorPath = "/error"
	// Service configuration file
	configurationFile = "config/tls.json"
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

// Global variables
var (
	tlsConfig      JSONConfigurationTLS
	tlsPath        TLSPath
	adminConfig    JSONConfigurationAdmin
	localUsers     map[string]LocalAuthUser
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
	// TLS Admin values
	adminRaw := viper.Sub("admin")
	err = adminRaw.Unmarshal(&adminConfig)
	if err != nil {
		return err
	}
	// Load configuration for the auth method
	switch adminConfig.Auth {
	case "local":
		usersRaw := viper.Sub("users")
		err = usersRaw.Unmarshal(&localUsers)
		if err != nil {
			return err
		}
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
	// Generate cookie store
	if adminConfig.Auth != noAuthLogin {
		storeKey = securecookie.GenerateRandomKey(32)
		store = sessions.NewCookieStore(storeKey)
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

	// Launch HTTP server for TLS endpoint
	go func() {
		serviceTLS := tlsConfig.Listener + ":" + tlsConfig.Port
		log.Printf("HTTP enroll listening %s", serviceTLS)
		log.Fatal(http.ListenAndServe(serviceTLS, routerTLS))
	}()

	// Launch HTTP server for admin
	go func() {
		serviceAdmin := adminConfig.Listener + ":" + adminConfig.Port
		log.Printf("HTTP admin listening %s", serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}()

	<-finish
}

// Get PostgreSQL DB using GORM
func getDB() *gorm.DB {
	t := "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable"
	postgresDSN := fmt.Sprintf(
		t, dbConfig.Host, dbConfig.Port, dbConfig.Name, dbConfig.Username, dbConfig.Password)
	db, err := gorm.Open("postgres", postgresDSN)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	// Performance settings for DB access
	db.DB().SetMaxIdleConns(20)
	db.DB().SetMaxOpenConns(100)
	db.DB().SetConnMaxLifetime(time.Second * 30)

	return db
}

// Automigrate of tables
func automigrateDB() error {
	var err error
	// table osquery_nodes
	err = db.AutoMigrate(OsqueryNode{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_nodes): %v", err)
	}
	// table archive_osquery_nodes
	err = db.AutoMigrate(ArchiveOsqueryNode{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (archive_osquery_nodes): %v", err)
	}
	// table node_history_ipaddress
	err = db.AutoMigrate(NodeHistoryIPAddress{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_ipaddress): %v", err)
	}
	// table geo_location_ipaddress
	err = db.AutoMigrate(GeoLocationIPAddress{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (geo_location_ipaddress): %v", err)
	}
	// table node_history_hostname
	err = db.AutoMigrate(NodeHistoryHostname{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_hostname): %v", err)
	}
	// table node_history_localname
	err = db.AutoMigrate(NodeHistoryLocalname{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_localname): %v", err)
	}
	// table node_history_username
	err = db.AutoMigrate(NodeHistoryUsername{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_username): %v", err)
	}
	// table distributed_queries
	err = db.AutoMigrate(DistributedQuery{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_queries): %v", err)
	}
	// table distributed_query_executions
	err = db.AutoMigrate(DistributedQueryExecution{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_query_executions): %v", err)
	}
	// table distributed_query_targets
	err = db.AutoMigrate(DistributedQueryTarget{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_query_targets): %v", err)
	}
	// table osquery_status_data
	err = db.AutoMigrate(OsqueryStatusData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_status_data): %v", err)
	}
	// table osquery_result_data
	err = db.AutoMigrate(OsqueryResultData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_result_data): %v", err)
	}
	// table osquery_query_data
	err = db.AutoMigrate(OsqueryQueryData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_query_data): %v", err)
	}
	return nil
}
