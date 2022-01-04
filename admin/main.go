package main

import (
	"crypto/rsa"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	ahandlers "github.com/jmpsec/osctrl/admin/handlers"
	"github.com/jmpsec/osctrl/admin/sessions"
	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/logging"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/version"
	"github.com/spf13/viper"
)

// Constants for the service
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + settings.ServiceAdmin
	// Service version
	serviceVersion string = version.OsctrlVersion
	// Service description
	serviceDescription string = "Admin service for osctrl"
	// Application description
	appDescription string = serviceDescription + ", a fast and efficient osquery management"
)

// Paths
const (
	// Default endpoint to handle HTTP health
	healthPath string = "/health"
	// Default endpoint to handle Login
	loginPath string = "/login"
	// Default endpoint to handle HTTP(500) errors
	errorPath string = "/error"
	// Default endpoint to handle Forbidden(403) errors
	forbiddenPath string = "/forbidden"
	// Default endpoint for favicon
	faviconPath string = "/favicon.ico"
)

// Configuration
const (
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
	// Default TLS certificate file
	tlsCertificateFile string = "config/tls.crt"
	// Default TLS private key file
	tlsKeyFile string = "config/tls.key"
)

// Random
const (
	// Static files folder
	staticFilesFolder string = "./static"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default hours to classify nodes as inactive
	defaultInactive int = -72
	// Hourly interval to cleanup logs
	hourlyInterval int = 60
)

// osquery
const (
	// osquery version to display tables
	osqueryTablesVersion string = "5.0.1"
	// JSON file with osquery tables data
	osqueryTablesFile string = "data/" + osqueryTablesVersion + ".json"
)

var (
	// Wait for backend in seconds
	backendWait = 7 * time.Second
)

// Global general variables
var (
	err         error
	adminConfig types.JSONConfigurationService
	db          *gorm.DB
	settingsmgr *settings.Settings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	carvesmgr   *carves.Carves
	sessionsmgr *sessions.SessionManager
	envs        *environments.Environment
	adminUsers  *users.UserManager
	tagsmgr     *tags.TagManager
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []types.OsqueryTable
	adminMetrics  *metrics.Metrics
	handlersAdmin *ahandlers.HandlersAdmin
	loggerDB      *logging.LoggerDB
)

// Variables for flags
var (
	versionFlag *bool
	configFlag  *string
	dbFlag      *string
	samlFlag    *string
	headersFlag *string
	jwtFlag     *string
	tlsServer   *bool
	tlsCert     *string
	tlsKey      *string
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
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Admin values
	adminRaw := viper.Sub(service)
	if err := adminRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method")
	}
	for _, _l := range cfg.Logging {
		if !validLogging[_l] {
			return cfg, fmt.Errorf("Invalid logging method")
		}
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	log.Printf("==================== Initializing %s v%s", serviceName, serviceVersion)
	// Command line flags
	flag.Usage = adminUsage
	// Define flags
	versionFlag = flag.Bool("v", false, "Displays the binary version.")
	configFlag = flag.String("c", configurationFile, "Service configuration JSON file to use.")
	dbFlag = flag.String("D", dbConfigurationFile, "DB configuration JSON file to use.")
	samlFlag = flag.String("S", samlConfigurationFile, "SAML configuration JSON file to use.")
	headersFlag = flag.String("H", headersConfigurationFile, "Headers configuration JSON file to use.")
	jwtFlag = flag.String("J", jwtConfigurationFile, "JWT configuration JSON file to use.")
	tlsServer = flag.Bool("tls", false, "TLS termination is enabled. It requires certificate and key.")
	tlsCert = flag.String("cert", tlsCertificateFile, "Certificate file to be used for TLS.")
	tlsKey = flag.String("key", tlsKeyFile, "Private key file to be used for TLS.")
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
	log.Printf("==================== Starting %s v%s", serviceName, serviceVersion)
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
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close Database handler - %v", err)
		}
	}()
	// Initialize users
	adminUsers = users.CreateUserManager(db, &jwtConfig)
	// Initialize tags
	tagsmgr = tags.CreateTagManager(db)
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
	sessionsmgr = sessions.CreateSessionManager(db, projectName)
	// Initialize service settings
	log.Println("Loading service settings")
	if err := loadingSettings(settingsmgr); err != nil {
		log.Fatalf("Error loading settings - %v", err)
	}
	// Initialize metrics
	log.Println("Loading service metrics")
	adminMetrics, err = loadingMetrics(settingsmgr)
	if err != nil {
		log.Fatalf("Error loading metrics - %v", err)
	}
	// Initialize DB logger
	loggerDB, err = logging.CreateLoggerDB(*dbFlag, backend.DBKey)
	if err != nil {
		log.Fatalf("Error loading logger - %v", err)
	}
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
			AllowIDPInitiated: true,
		})
		if err != nil {
			log.Fatalf("Can not initialize SAML Middleware %s", err)
		}
	}

	// FIXME Redis cache - Ticker to cleanup sessions
	// FIXME splay this?
	go func() {
		_t := settingsmgr.CleanupSessions()
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			if settingsmgr.DebugService(settings.ServiceAdmin) {
				log.Println("DebugService: Cleaning up sessions")
			}
			sessionsmgr.Cleanup()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// Cleaning up status/result/query logs
	go func() {
		for {
			_e, err := envs.All()
			if err != nil {
				log.Printf("error getting environments when cleaning up logs - %v", err)
			}
			for _, e := range _e {
				if settingsmgr.CleanStatusLogs() {
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Println("DebugService: Cleaning up status logs")
					}
					if err := loggerDB.CleanStatusLogs(e.Name, settingsmgr.CleanStatusInterval()); err != nil {
						log.Printf("error cleaning up status logs - %v", err)
					}
				}
				if settingsmgr.CleanResultLogs() {
					if settingsmgr.DebugService(settings.ServiceAdmin) {
						log.Println("DebugService: Cleaning up result logs")
					}
					if err := loggerDB.CleanResultLogs(e.Name, settingsmgr.CleanResultInterval()); err != nil {
						log.Printf("error cleaning up result logs - %v", err)
					}
				}
			}
			if settingsmgr.CleanQueryLogs() {
				if settingsmgr.DebugService(settings.ServiceAdmin) {
					log.Println("DebugService: Cleaning up query logs")
				}
				if err := loggerDB.CleanQueryLogs(settingsmgr.CleanQueryEntries()); err != nil {
					log.Printf("error cleaning up query logs - %v", err)
				}
			}
			time.Sleep(time.Duration(hourlyInterval) * time.Second)
		}
	}()

	// Initialize Admin handlers before router
	handlersAdmin = ahandlers.CreateHandlersAdmin(
		ahandlers.WithDB(db),
		ahandlers.WithEnvs(envs),
		ahandlers.WithUsers(adminUsers),
		ahandlers.WithTags(tagsmgr),
		ahandlers.WithNodes(nodesmgr),
		ahandlers.WithQueries(queriesmgr),
		ahandlers.WithCarves(carvesmgr),
		ahandlers.WithSettings(settingsmgr),
		ahandlers.WithMetrics(adminMetrics),
		ahandlers.WithLoggerDB(loggerDB),
		ahandlers.WithSessions(sessionsmgr),
		ahandlers.WithVersion(serviceVersion),
		ahandlers.WithOsqueryTables(osqueryTables),
		ahandlers.WithAdminConfig(&adminConfig),
	)

	// ////////////////////////// ADMIN
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Creating router")
	}
	// Create router for admin
	routerAdmin := mux.NewRouter()

	// ///////////////////////// UNAUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Unauthenticated content")
	}
	// Admin: login only if local auth is enabled
	if adminConfig.Auth != settings.AuthNone {
		// login
		routerAdmin.HandleFunc(loginPath, handlersAdmin.LoginHandler).Methods("GET")
		routerAdmin.HandleFunc(loginPath, handlersAdmin.LoginPOSTHandler).Methods("POST")
	}
	// Admin: health of service
	routerAdmin.HandleFunc(healthPath, handlersAdmin.HealthHandler).Methods("GET")
	// Admin: error
	routerAdmin.HandleFunc(errorPath, handlersAdmin.ErrorHandler).Methods("GET")
	// Admin: forbidden
	routerAdmin.HandleFunc(forbiddenPath, handlersAdmin.ForbiddenHandler).Methods("GET")
	// Admin: favicon
	routerAdmin.HandleFunc(faviconPath, handlersAdmin.FaviconHandler)
	// Admin: static
	routerAdmin.PathPrefix("/static/").Handler(
		http.StripPrefix("/static", http.FileServer(http.Dir(staticFilesFolder))))

	// ///////////////////////// AUTHENTICATED CONTENT
	if settingsmgr.DebugService(settings.ServiceAdmin) {
		log.Println("DebugService: Authenticated content")
	}
	// Admin: JSON data for environments
	routerAdmin.Handle("/json/environment/{environment}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONEnvironmentHandler))).Methods("GET")
	// Admin: JSON data for platforms
	routerAdmin.Handle("/json/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONPlatformHandler))).Methods("GET")
	// Admin: JSON data for logs
	routerAdmin.Handle("/json/logs/{type}/{environment}/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONLogsHandler))).Methods("GET")
	// Admin: JSON data for query logs
	routerAdmin.Handle("/json/query/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryLogsHandler))).Methods("GET")
	// Admin: JSON data for sidebar stats
	routerAdmin.Handle("/json/stats/{target}/{identifier}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONStatsHandler))).Methods("GET")
	// Admin: JSON data for tags
	routerAdmin.Handle("/json/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONTagsHandler))).Methods("GET")
	// Admin: table for environments
	routerAdmin.Handle("/environment/{environment}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvironmentHandler))).Methods("GET")
	// Admin: table for platforms
	routerAdmin.Handle("/platform/{platform}/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PlatformHandler))).Methods("GET")
	// Admin: dashboard
	routerAdmin.Handle("/dashboard", handlerAuthCheck(http.HandlerFunc(handlersAdmin.RootHandler))).Methods("GET")
	// Admin: root
	routerAdmin.Handle("/", handlerAuthCheck(http.HandlerFunc(handlersAdmin.RootHandler))).Methods("GET")
	// Admin: node view
	routerAdmin.Handle("/node/{uuid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeHandler))).Methods("GET")
	// Admin: multi node action
	routerAdmin.Handle("/node/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeActionsPOSTHandler))).Methods("POST")
	// Admin: run queries
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/query/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunPOSTHandler))).Methods("POST")
	// Admin: list queries
	routerAdmin.Handle("/query/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryListGETHandler))).Methods("GET")
	// Admin: saved queries
	routerAdmin.Handle("/query/saved", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SavedQueriesGETHandler))).Methods("GET")
	// Admin: query actions
	routerAdmin.Handle("/query/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryActionsPOSTHandler))).Methods("POST")
	// Admin: query JSON
	routerAdmin.Handle("/query/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryHandler))).Methods("GET")
	// Admin: query logs
	routerAdmin.Handle("/query/logs/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryLogsHandler))).Methods("GET")
	// Admin: carve files
	routerAdmin.Handle("/carves/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunGETHandler))).Methods("GET")
	routerAdmin.Handle("/carves/run", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunPOSTHandler))).Methods("POST")
	// Admin: list carves
	routerAdmin.Handle("/carves/list", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesListGETHandler))).Methods("GET")
	// Admin: carves actions
	routerAdmin.Handle("/carves/actions", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesActionsPOSTHandler))).Methods("POST")
	// Admin: carves JSON
	routerAdmin.Handle("/carves/json/{target}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONCarvesHandler))).Methods("GET")
	// Admin: carves details
	routerAdmin.Handle("/carves/details/{name}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDetailsHandler))).Methods("GET")
	// Admin: carves download
	routerAdmin.Handle("/carves/download/{sessionid}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDownloadHandler))).Methods("GET")
	// Admin: nodes configuration
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfGETHandler))).Methods("GET")
	routerAdmin.Handle("/conf/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/intervals/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.IntervalsPOSTHandler))).Methods("POST")
	// Admin: nodes enroll
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollGETHandler))).Methods("GET")
	routerAdmin.Handle("/enroll/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/expiration/{environment}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.ExpirationPOSTHandler))).Methods("POST")
	// Admin: server settings
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsGETHandler))).Methods("GET")
	routerAdmin.Handle("/settings/{service}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsPOSTHandler))).Methods("POST")
	// Admin: manage environments
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsGETHandler))).Methods("GET")
	routerAdmin.Handle("/environments", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsPOSTHandler))).Methods("POST")
	// Admin: manage users
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersGETHandler))).Methods("GET")
	routerAdmin.Handle("/users", handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsGETHandler))).Methods("GET")
	routerAdmin.Handle("/users/permissions/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsPOSTHandler))).Methods("POST")
	// Admin: manage tags
	routerAdmin.Handle("/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsGETHandler))).Methods("GET")
	routerAdmin.Handle("/tags", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsPOSTHandler))).Methods("POST")
	routerAdmin.Handle("/tags/nodes", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagNodesPOSTHandler))).Methods("POST")
	// Admin: manage tokens
	routerAdmin.Handle("/tokens/{username}", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensGETHandler))).Methods("GET")
	routerAdmin.Handle("/tokens/{username}/refresh", handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensPOSTHandler))).Methods("POST")
	// edit profile
	routerAdmin.Handle("/profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfileGETHandler))).Methods("GET")
	routerAdmin.Handle("/profile", handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfilePOSTHandler))).Methods("POST")
	// logout
	routerAdmin.Handle("/logout", handlerAuthCheck(http.HandlerFunc(handlersAdmin.LogoutPOSTHandler))).Methods("POST")
	// SAML ACS
	if adminConfig.Auth == settings.AuthSAML {
		routerAdmin.PathPrefix("/saml/").Handler(samlMiddleware)
	}

	// Launch HTTP server for admin
	serviceAdmin := adminConfig.Listener + ":" + adminConfig.Port
	if *tlsServer {
		cfg := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
		srv := &http.Server{
			Addr:         serviceAdmin,
			Handler:      routerAdmin,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Printf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceAdmin)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceAdmin)
		log.Fatal(http.ListenAndServe(serviceAdmin, routerAdmin))
	}
}
