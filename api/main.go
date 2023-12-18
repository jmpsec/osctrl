package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/cache"
	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/metrics"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/version"
	"github.com/urfave/cli/v2"

	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

const (
	// Project name
	projectName = "osctrl"
	// Service name
	serviceName = projectName + "-" + settings.ServiceAPI
	// Service version
	serviceVersion = version.OsctrlVersion
	// Service description
	serviceDescription = "API service for osctrl"
	// Application description
	appDescription = serviceDescription + ", a fast and efficient osquery management"
	// Default service configuration file
	defConfigurationFile = "config/" + settings.ServiceAPI + ".json"
	// Default DB configuration file
	defDBConfigurationFile = "config/db.json"
	// Default redis configuration file
	defRedisConfigurationFile = "config/redis.json"
	// Default TLS certificate file
	defTLSCertificateFile = "config/tls.crt"
	// Default TLS private key file
	defTLSKeyFile = "config/tls.key"
	// Default JWT configuration file
	defJWTConfigurationFile = "config/jwt.json"
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default timeout to attempt backend reconnect
	defaultBackendRetryTimeout int = 7
	// Default timeout to attempt redis reconnect
	defaultRedisRetryTimeout int = 7
)

// Paths
const (
	// HTTP health path
	healthPath = "/health"
	// HTTP errors path
	errorPath     = "/error"
	forbiddenPath = "/forbidden"
	// API prefix path
	apiPrefixPath = "/api"
	// API version path
	apiVersionPath = "/v1"
	// API login path
	apiLoginPath = "/login"
	// API nodes path
	apiNodesPath = "/nodes"
	// API queries path
	apiQueriesPath = "/queries"
	// API users path
	apiUsersPath = "/users"
	// API all queries path
	apiAllQueriesPath = "/all-queries"
	// API carves path
	apiCarvesPath = "/carves"
	// API platforms path
	apiPlatformsPath = "/platforms"
	// API environments path
	apiEnvironmentsPath = "/environments"
	// API tags path
	apiTagsPath = "/tags"
	// API settings path
	apiSettingsPath = "/settings"
)

// Global variables
var (
	err         error
	apiConfig   types.JSONConfigurationAPI
	dbConfig    backend.JSONConfigurationDB
	redisConfig cache.JSONConfigurationRedis
	jwtConfig   types.JSONConfigurationJWT
	db          *backend.DBManager
	redis       *cache.RedisManager
	apiUsers    *users.UserManager
	tagsmgr     *tags.TagManager
	settingsmgr *settings.Settings
	envs        *environments.Environment
	envsmap     environments.MapEnvironments
	settingsmap settings.MapSettings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	filecarves  *carves.Carves
	_metrics    *metrics.Metrics
	app         *cli.App
	flags       []cli.Flag
)

// Variables for flags
var (
	configFlag        bool
	serviceConfigFile string
	redisConfigFile   string
	dbFlag            bool
	redisFlag         bool
	dbConfigFile      string
	loggerValue       string
	jwtFlag           bool
	jwtConfigFile     string
	tlsServer         bool
	tlsCertFile       string
	tlsKeyFile        string
)

// Valid values for auth and logging in configuration
var validAuth = map[string]bool{
	settings.AuthNone: true,
	settings.AuthJWT:  true,
}

// Function to load the configuration file and assign to variables
func loadConfiguration(file, service string) (types.JSONConfigurationAPI, error) {
	var cfg types.JSONConfigurationAPI
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// API values
	apiRaw := viper.Sub(service)
	if apiRaw == nil {
		return cfg, fmt.Errorf("JSON key %s not found in %s", service, file)
	}
	if err := apiRaw.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Auth] {
		return cfg, fmt.Errorf("Invalid auth method: '%s'", cfg.Auth)
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Provide service configuration via JSON file",
			EnvVars:     []string{"SERVICE_CONFIG"},
			Destination: &configFlag,
		},
		&cli.StringFlag{
			Name:        "config-file",
			Aliases:     []string{"C"},
			Value:       defConfigurationFile,
			Usage:       "Load service configuration from `FILE`",
			EnvVars:     []string{"SERVICE_CONFIG_FILE"},
			Destination: &serviceConfigFile,
		},
		&cli.StringFlag{
			Name:        "listener",
			Aliases:     []string{"l"},
			Value:       "0.0.0.0",
			Usage:       "Listener for the service",
			EnvVars:     []string{"SERVICE_LISTENER"},
			Destination: &apiConfig.Listener,
		},
		&cli.StringFlag{
			Name:        "port",
			Aliases:     []string{"p"},
			Value:       "9002",
			Usage:       "TCP port for the service",
			EnvVars:     []string{"SERVICE_PORT"},
			Destination: &apiConfig.Port,
		},
		&cli.StringFlag{
			Name:        "auth",
			Aliases:     []string{"A"},
			Value:       settings.AuthNone,
			Usage:       "Authentication mechanism for the service",
			EnvVars:     []string{"SERVICE_AUTH"},
			Destination: &apiConfig.Auth,
		},
		&cli.StringFlag{
			Name:        "host",
			Aliases:     []string{"H"},
			Value:       "0.0.0.0",
			Usage:       "Exposed hostname the service uses",
			EnvVars:     []string{"SERVICE_HOST"},
			Destination: &apiConfig.Host,
		},
		&cli.StringFlag{
			Name:        "logging",
			Aliases:     []string{"L"},
			Value:       settings.LoggingNone,
			Usage:       "Logging mechanism to handle logs from nodes",
			EnvVars:     []string{"SERVICE_LOGGER"},
			Destination: &loggerValue,
		},
		&cli.BoolFlag{
			Name:        "redis",
			Aliases:     []string{"r"},
			Value:       false,
			Usage:       "Provide redis configuration via JSON file",
			EnvVars:     []string{"REDIS_CONFIG"},
			Destination: &redisFlag,
		},
		&cli.StringFlag{
			Name:        "redis-file",
			Aliases:     []string{"R"},
			Value:       defRedisConfigurationFile,
			Usage:       "Load redis configuration from `FILE`",
			EnvVars:     []string{"REDIS_CONFIG_FILE"},
			Destination: &redisConfigFile,
		},
		&cli.StringFlag{
			Name:        "redis-connection-string",
			Value:       "",
			Usage:       "Redis connection string, must include schema (<redis|rediss|unix>://<user>:<pass>@<host>:<port>/<db>?<options>",
			EnvVars:     []string{"REDIS_CONNECTION_STRING"},
			Destination: &redisConfig.ConnectionString,
		},
		&cli.StringFlag{
			Name:        "redis-host",
			Value:       "127.0.0.1",
			Usage:       "Redis host to be connected to",
			EnvVars:     []string{"REDIS_HOST"},
			Destination: &redisConfig.Host,
		},
		&cli.StringFlag{
			Name:        "redis-port",
			Value:       "6379",
			Usage:       "Redis port to be connected to",
			EnvVars:     []string{"REDIS_PORT"},
			Destination: &redisConfig.Port,
		},
		&cli.StringFlag{
			Name:        "redis-pass",
			Value:       "",
			Usage:       "Password to be used for redis",
			EnvVars:     []string{"REDIS_PASS"},
			Destination: &redisConfig.Password,
		},
		&cli.IntFlag{
			Name:        "redis-db",
			Value:       0,
			Usage:       "Redis database to be selected after connecting",
			EnvVars:     []string{"REDIS_DB"},
			Destination: &redisConfig.DB,
		},
		&cli.IntFlag{
			Name:        "redis-conn-retry",
			Value:       defaultRedisRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the cache, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"REDIS_CONN_RETRY"},
			Destination: &redisConfig.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &dbFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &dbConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbConfig.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbConfig.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbConfig.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbConfig.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbConfig.Password,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbConfig.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbConfig.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConfig.ConnMaxLifetime,
		},
		&cli.IntFlag{
			Name:        "db-conn-retry",
			Value:       defaultBackendRetryTimeout,
			Usage:       "Time in seconds to retry the connection to the database, if set to 0 the service will stop if the connection fails",
			EnvVars:     []string{"DB_CONN_RETRY"},
			Destination: &dbConfig.ConnRetry,
		},
		&cli.BoolFlag{
			Name:        "tls",
			Aliases:     []string{"t"},
			Value:       false,
			Usage:       "Enable TLS termination. It requires certificate and key",
			EnvVars:     []string{"TLS_SERVER"},
			Destination: &tlsServer,
		},
		&cli.StringFlag{
			Name:        "cert",
			Aliases:     []string{"T"},
			Value:       defTLSCertificateFile,
			Usage:       "TLS termination certificate from `FILE`",
			EnvVars:     []string{"TLS_CERTIFICATE"},
			Destination: &tlsCertFile,
		},
		&cli.StringFlag{
			Name:        "key",
			Aliases:     []string{"K"},
			Value:       defTLSKeyFile,
			Usage:       "TLS termination private key from `FILE`",
			EnvVars:     []string{"TLS_KEY"},
			Destination: &tlsKeyFile,
		},
		&cli.BoolFlag{
			Name:        "jwt",
			Aliases:     []string{"j"},
			Value:       false,
			Usage:       "Provide JWT configuration via JSON file",
			EnvVars:     []string{"JWT_CONFIG"},
			Destination: &jwtFlag,
		},
		&cli.StringFlag{
			Name:        "jwt-file",
			Value:       defJWTConfigurationFile,
			Usage:       "Load JWT configuration from `FILE`",
			EnvVars:     []string{"JWT_CONFIG_FILE"},
			Destination: &jwtConfigFile,
		},
		&cli.StringFlag{
			Name:        "jwt-secret",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"JWT_SECRET"},
			Destination: &jwtConfig.JWTSecret,
		},
		&cli.IntFlag{
			Name:        "jwt-expire",
			Value:       3,
			Usage:       "Maximum amount of hours for the tokens to expire",
			EnvVars:     []string{"JWT_EXPIRE"},
			Destination: &jwtConfig.HoursToExpire,
		},
	}
	// Logging format flags
	log.SetFlags(log.Lshortfile)
}

// Go go!
func osctrlAPIService() {
	// ////////////////////////////// Backend
	log.Println("Initializing backend...")
	for {
		db, err = backend.CreateDBManager(dbConfig)
		if db != nil {
			log.Println("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Printf("Failed to connect to backend - %v", err)
			if dbConfig.ConnRetry == 0 {
				log.Fatalf("Connection to backend failed and no retry was set")
			}
		}
		log.Printf("Backend NOT ready! Retrying in %d seconds...\n", dbConfig.ConnRetry)
		time.Sleep(time.Duration(dbConfig.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Println("Initializing cache...")
	for {
		redis, err = cache.CreateRedisManager(redisConfig)
		if redis != nil {
			log.Println("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Printf("Failed to connect to cache - %v", err)
			if redisConfig.ConnRetry == 0 {
				log.Fatalf("Connection to cache failed and no retry was set")
			}
		}
		log.Printf("Cache NOT ready! Retrying in %d seconds...\n", redisConfig.ConnRetry)
		time.Sleep(time.Duration(redisConfig.ConnRetry) * time.Second)
	}
	log.Println("Initialize users")
	apiUsers = users.CreateUserManager(db.Conn, &jwtConfig)
	log.Println("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Println("Initialize environment")
	envs = environments.CreateEnvironment(db.Conn)
	// Initialize settings
	log.Println("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Println("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Println("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Println("Initialize carves")
	filecarves = carves.CreateFileCarves(db.Conn, apiConfig.Carver, nil)
	log.Println("Loading service settings")
	loadingSettings()
	// Ticker to reload environments
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Environments ticker")
	}
	// Refresh environments as soon as service starts
	go func() {
		_t := settingsmgr.RefreshEnvs(settings.ServiceAPI)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			envsmap = refreshEnvironments()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// Ticker to reload settings
	// FIXME Implement Redis cache
	// FIXME splay this?
	if settingsmgr.DebugService(settings.ServiceAPI) {
		log.Println("DebugService: Settings ticker")
	}
	// Refresh settings as soon as the service starts
	go func() {
		_t := settingsmgr.RefreshSettings(settings.ServiceAPI)
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			settingsmap = refreshSettings()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()

	// ///////////////////////// API
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

	// ///////////////////////// UNAUTHENTICATED
	routerAPI.Handle(_apiPath(apiLoginPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiLoginHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiLoginPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiLoginHandler))).Methods("POST")
	// ///////////////////////// AUTHENTICATED
	// API: nodes by environment
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/node/{node}", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/node/{node}/", handlerAuthCheck(http.HandlerFunc(apiNodeHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/delete", handlerAuthCheck(http.HandlerFunc(apiDeleteNodeHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/delete/", handlerAuthCheck(http.HandlerFunc(apiDeleteNodeHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/all", handlerAuthCheck(http.HandlerFunc(apiAllNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/all/", handlerAuthCheck(http.HandlerFunc(apiAllNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/active", handlerAuthCheck(http.HandlerFunc(apiActiveNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/active/", handlerAuthCheck(http.HandlerFunc(apiActiveNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/inactive", handlerAuthCheck(http.HandlerFunc(apiInactiveNodesHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiNodesPath)+"/{env}/inactive/", handlerAuthCheck(http.HandlerFunc(apiInactiveNodesHandler))).Methods("GET")
	// API: queries by environment
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiQueriesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/results/{name}", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiQueriesPath)+"/{env}/results/{name}/", handlerAuthCheck(http.HandlerFunc(apiQueryResultsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath+"/{env}"), handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiAllQueriesPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiAllQueriesShowHandler))).Methods("GET")
	// API: carves by environment
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiCarvesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiCarvesShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiCarvesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiCarvesRunHandler))).Methods("POST")
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}/{name}", handlerAuthCheck(http.HandlerFunc(apiCarveShowHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiCarvesPath)+"/{env}/{name}/", handlerAuthCheck(http.HandlerFunc(apiCarveShowHandler))).Methods("GET")
	// API: users by environment
	routerAPI.Handle(_apiPath(apiUsersPath)+"/{username}", handlerAuthCheck(http.HandlerFunc(apiUserHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiUsersPath)+"/{username}/", handlerAuthCheck(http.HandlerFunc(apiUserHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiUsersPath), handlerAuthCheck(http.HandlerFunc(apiUsersHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiUsersPath)+"/", handlerAuthCheck(http.HandlerFunc(apiUsersHandler))).Methods("GET")
	// API: platforms by environment
	routerAPI.Handle(_apiPath(apiPlatformsPath), handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiPlatformsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiPlatformsHandler))).Methods("GET")
	// API: environments by environment
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{env}", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/{env}/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath), handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiEnvironmentsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiEnvironmentsHandler))).Methods("GET")
	// API: tags by environment
	routerAPI.Handle(_apiPath(apiTagsPath), handlerAuthCheck(http.HandlerFunc(apiTagsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiTagsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiTagsHandler))).Methods("GET")
	// API: settings by environment
	routerAPI.Handle(_apiPath(apiSettingsPath), handlerAuthCheck(http.HandlerFunc(apiSettingsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/", handlerAuthCheck(http.HandlerFunc(apiSettingsHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/{env}", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceEnvHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/{env}/", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceEnvHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/json", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceJSONHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/json/", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceJSONHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/json/{env}", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceEnvJSONHandler))).Methods("GET")
	routerAPI.Handle(_apiPath(apiSettingsPath)+"/{service}/json/{env}/", handlerAuthCheck(http.HandlerFunc(apiSettingsServiceEnvJSONHandler))).Methods("GET")

	// Launch listeners for API server
	serviceListener := apiConfig.Listener + ":" + apiConfig.Port
	if tlsServer {
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
			Addr:         serviceListener,
			Handler:      routerAPI,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Printf("%s v%s - HTTPS listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile))
	} else {
		log.Printf("%s v%s - HTTP listening %s", serviceName, serviceVersion, serviceListener)
		log.Fatal(http.ListenAndServe(serviceListener, routerAPI))
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(c *cli.Context) error {
	// Load configuration if external JSON config file is used
	if configFlag {
		apiConfig, err = loadConfiguration(serviceConfigFile, settings.ServiceAPI)
		if err != nil {
			return fmt.Errorf("Failed to load service configuration %s - %s", serviceConfigFile, err)
		}
	}
	// Load DB configuration if external JSON config file is used
	if dbFlag {
		dbConfig, err = backend.LoadConfiguration(dbConfigFile, backend.DBKey)
		if err != nil {
			return fmt.Errorf("Failed to load DB configuration - %v", err)
		}
	}
	// Load redis configuration if external JSON config file is used
	if redisFlag {
		redisConfig, err = cache.LoadConfiguration(redisConfigFile, cache.RedisKey)
		if err != nil {
			return fmt.Errorf("Failed to load redis configuration - %v", err)
		}
	}
	// Load JWT configuration if external JWT JSON config file is used
	if jwtFlag {
		jwtConfig, err = loadJWTConfiguration(jwtConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to load JWT configuration - %v", err)
		}
	}
	return nil
}

func main() {
	// Initiate CLI and parse arguments
	app = cli.NewApp()
	app.Name = serviceName
	app.Usage = appDescription
	app.Version = serviceVersion
	app.Description = appDescription
	app.Flags = flags
	// Define this command for help to exit when help flag is passed
	app.Commands = []*cli.Command{
		{
			Name: "help",
			Action: func(c *cli.Context) error {
				cli.ShowAppHelpAndExit(c, 0)
				return nil
			},
		},
	}
	app.Action = cliAction
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	// Service starts!
	osctrlAPIService()
}
