package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/jmpsec/osctrl/cmd/admin/handlers"
	"github.com/jmpsec/osctrl/cmd/admin/sessions"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
)

// Constants for the service
const (
	// Project name
	projectName string = "osctrl"
	// Service name
	serviceName string = projectName + "-" + config.ServiceAdmin
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
	// Default endpoint to handle Logout
	logoutPath string = "/logout"
	// Default endpoint to handle HTTP(500) errors
	errorPath string = "/error"
	// Default endpoint to handle Forbidden(403) errors
	forbiddenPath string = "/forbidden"
	// Default endpoint for favicon
	faviconPath string = "/favicon.ico"
)

// Random
const (
	// Default refreshing interval in seconds
	defaultRefresh int = 300
	// Default interval in seconds to expire queries/carves
	defaultExpiration int = 900
	// Default hours to classify nodes as inactive
	defaultInactive int = 72
)

// Build-time metadata (overridden via -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...")
var (
	buildVersion = version.OsctrlVersion
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// Global general variables
var (
	err         error
	db          *backend.DBManager
	redis       *cache.RedisManager
	settingsmgr *settings.Settings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	carvesmgr   *carves.Carves
	sessionsmgr *sessions.SessionManager
	envs        *environments.EnvManager
	adminUsers  *users.UserManager
	tagsmgr     *tags.TagManager
	carvers3    *carves.CarverS3
	app         *cli.Command
	flags       []cli.Flag
	// FIXME this struct is temporary until we refactor to write settings to the DB
	flagParams           *config.ServiceParameters
	serviceConfiguration config.AdminConfiguration
	// FIXME this is nasty and should not be a global but here we are
	osqueryTables []types.OsqueryTable
	handlersAdmin *handlers.HandlersAdmin
	auditLog      *auditlog.AuditLogManager
)

// SAML variables
var (
	samlMiddleware *samlsp.Middleware
	samlConfig     config.YAMLConfigurationSAML
	samlData       samlThings
)

// Valid values for auth in configuration
var validAuth = map[string]bool{
	config.AuthDB:   true,
	config.AuthSAML: true,
	config.AuthJSON: true,
}

// Valid values for carver in configuration
var validCarver = map[string]bool{
	config.CarverDB:    true,
	config.CarverLocal: true,
	config.CarverS3:    true,
}

// Function to load the configuration from a single YAML file
func loadYAMLConfiguration(file string) (config.AdminConfiguration, error) {
	var cfg config.AdminConfiguration
	// Load file and read config
	viper.SetConfigFile(file)
	viper.SetConfigType(config.YAMLConfigType)
	if err := viper.ReadInConfig(); err != nil {
		return cfg, err
	}
	// Unmarshal into struct
	if err := viper.Unmarshal(&cfg); err != nil {
		return cfg, err
	}
	// Check if values are valid
	if !validAuth[cfg.Service.Auth] {
		return cfg, fmt.Errorf("invalid auth method")
	}
	if !validCarver[cfg.Carver.Type] {
		return cfg, fmt.Errorf("invalid carver method")
	}
	// No errors!
	return cfg, nil
}

// Initialization code
func init() {
	// Initialize default flagParams
	flagParams = &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{},
		DB:      &config.YAMLConfigurationDB{},
		Redis:   &config.YAMLConfigurationRedis{},
		Osquery: &config.YAMLConfigurationOsquery{},
		Osctrld: &config.YAMLConfigurationOsctrld{},
		SAML:    &config.YAMLConfigurationSAML{},
		JWT:     &config.YAMLConfigurationJWT{},
		TLS:     &config.YAMLConfigurationTLS{},
		Logger: &config.YAMLConfigurationLogger{
			DB:       &config.YAMLConfigurationDB{},
			S3:       &config.S3Logger{},
			Graylog:  &config.GraylogLogger{},
			Elastic:  &config.ElasticLogger{},
			Splunk:   &config.SplunkLogger{},
			Logstash: &config.LogstashLogger{},
			Kinesis:  &config.KinesisLogger{},
			Kafka:    &config.KafkaLogger{},
			Local:    &config.LocalLogger{},
		},
		Carver: &config.YAMLConfigurationCarver{
			S3:    &config.S3Carver{},
			Local: &config.LocalCarver{},
		},
		Admin: &config.YAMLConfigurationAdmin{},
		Debug: &config.YAMLConfigurationDebug{},
	}
	// Initialize CLI flags using the config package
	flags = config.InitAdminFlags(flagParams)
}

// Go go!
func osctrlAdminService() {
	// ////////////////////////////// Backend
	log.Info().Msg("Initializing backend...")
	for {
		db, err = backend.CreateDBManager(flagParams.DB)
		if db != nil {
			log.Info().Msg("Connection to backend successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to backend")
			if flagParams.DB.ConnRetry == 0 {
				log.Fatal().Msg("Connection to backend failed and no retry was set")
			}
		}
		log.Debug().Msgf("Backend NOT ready! Retrying in %d seconds...\n", flagParams.DB.ConnRetry)
		time.Sleep(time.Duration(flagParams.DB.ConnRetry) * time.Second)
	}
	// ////////////////////////////// Cache
	log.Info().Msg("Initializing cache...")
	for {
		redis, err = cache.CreateRedisManager(*flagParams.Redis)
		if redis != nil {
			log.Info().Msg("Connection to cache successful!")
			break
		}
		if err != nil {
			log.Err(err).Msg("Failed to connect to cache")
			if flagParams.Redis.ConnRetry == 0 {
				log.Fatal().Msg("Connection to cache failed and no retry was set")
			}
		}
		log.Debug().Msgf("Cache NOT ready! Retrying in %d seconds...\n", flagParams.Redis.ConnRetry)
		time.Sleep(time.Duration(flagParams.Redis.ConnRetry) * time.Second)
	}
	log.Info().Msg("Initialize users")
	adminUsers = users.CreateUserManager(db.Conn, flagParams.JWT)
	log.Info().Msg("Initialize tags")
	tagsmgr = tags.CreateTagManager(db.Conn)
	log.Info().Msg("Initialize environments")
	envs = environments.CreateEnvironment(db.Conn)
	log.Info().Msg("Initialize settings")
	settingsmgr = settings.NewSettings(db.Conn)
	log.Info().Msg("Initialize nodes")
	nodesmgr = nodes.CreateNodes(db.Conn)
	log.Info().Msg("Initialize queries")
	queriesmgr = queries.CreateQueries(db.Conn)
	log.Info().Msg("Initialize carves")
	carvesmgr = carves.CreateFileCarves(db.Conn, flagParams.Carver.Type, carvers3)
	log.Info().Msg("Initialize sessions")
	sessionsmgr = sessions.CreateSessionManager(db.Conn, authCookieName, flagParams.Admin.SessionKey)
	log.Info().Msg("Loading service settings")
	if err := loadingSettings(settingsmgr, flagParams); err != nil {
		log.Fatal().Msgf("Error loading settings - %v", err)
	}
	// Start SAML Middleware if we are using SAML
	if flagParams.Service.Auth == config.AuthSAML {
		log.Debug().Msg("SAML enabled for authentication")
		// Initialize SAML keypair to sign SAML Request.
		var err error
		samlData, err = keypairSAML(samlConfig)
		if err != nil {
			log.Fatal().Msgf("Can not initialize SAML keypair %s", err)
		}
		samlMiddleware, err = samlsp.New(samlsp.Options{
			URL:               *samlData.RootURL,
			Key:               samlData.KeyPair.PrivateKey.(*rsa.PrivateKey),
			Certificate:       samlData.KeyPair.Leaf,
			IDPMetadata:       samlData.IdpMetadata,
			AllowIDPInitiated: true,
		})
		if err != nil {
			log.Fatal().Msgf("Can not initialize SAML Middleware %s", err)
		}
	}
	// FIXME Redis cache - Ticker to cleanup sessions
	// FIXME splay this?
	log.Info().Msg("Initialize cleanup sessions")
	go func() {
		_t := settingsmgr.CleanupSessions()
		if _t == 0 {
			_t = int64(defaultRefresh)
		}
		for {
			log.Debug().Msg("Cleaning up sessions")
			sessionsmgr.Cleanup()
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	// Goroutine to cleanup expired queries and carves
	log.Info().Msg("Initialize cleanup queries/carves")
	go func() {
		_t := settingsmgr.CleanupExpired()
		if _t == 0 {
			_t = int64(defaultExpiration)
		}
		for {
			log.Debug().Msg("Cleaning up expired queries/carves")
			allEnvs, err := envs.All()
			if err != nil {
				log.Err(err).Msg("Error getting all environments")
			}
			for _, e := range allEnvs {
				// Periotically check if the queries are completed
				// not sure if we need to complete the Carves
				if err := queriesmgr.CleanupCompletedQueries(e.ID); err != nil {
					log.Err(err).Msg("Error completing expired queries")
				}
				// Periotically check if the queries are expired
				if err := queriesmgr.CleanupExpiredQueries(e.ID); err != nil {
					log.Err(err).Msg("Error cleaning up expired queries")
				}
				if err := queriesmgr.CleanupExpiredCarves(e.ID); err != nil {
					log.Err(err).Msg("Error cleaning up expired carves")
				}
			}
			time.Sleep(time.Duration(_t) * time.Second)
		}
	}()
	var loggerDBConfig *config.YAMLConfigurationDB
	// Set the logger configuration file if we have a DB logger
	if flagParams.Logger.Type == config.LoggingDB {
		if flagParams.Logger.LoggerDBSame {
			loggerDBConfig = flagParams.DB
		}
	}
	// Initialize audit log manager
	if flagParams.Service.AuditLog {
		log.Info().Msg("Initialize audit log (enabled)")
	} else {
		log.Info().Msg("Initialize audit log (disabled)")
	}
	auditLog, err = auditlog.CreateAuditLogManager(db.Conn, serviceName, flagParams.Service.AuditLog)
	if err != nil {
		log.Fatal().Msgf("Error initializing audit log manager - %v", err)
	}
	// Initialize Admin handlers before router
	log.Info().Msg("Initializing handlers")
	handlersAdmin = handlers.CreateHandlersAdmin(
		handlers.WithDB(db.Conn),
		handlers.WithEnvs(envs),
		handlers.WithUsers(adminUsers),
		handlers.WithTags(tagsmgr),
		handlers.WithNodes(nodesmgr),
		handlers.WithQueries(queriesmgr),
		handlers.WithCarves(carvesmgr),
		handlers.WithSettings(settingsmgr),
		handlers.WithCache(redis),
		handlers.WithSessions(sessionsmgr),
		handlers.WithMetadata(types.BuildMetadata{
			Version: buildVersion,
			Commit:  buildCommit,
			Date:    buildDate,
		}),
		handlers.WithOsqueryValues(*flagParams.Osquery),
		handlers.WithTemplates(flagParams.Admin.TemplatesDir),
		handlers.WithStaticLocation(flagParams.Admin.StaticOffline),
		handlers.WithOsqueryTables(osqueryTables),
		handlers.WithCarvesFolder(flagParams.Carver.Local.CarvesDir),
		handlers.WithConfiguration(flagParams),
		handlers.WithAuditLog(auditLog),
		handlers.WithDBLogger(loggerDBConfig),
		handlers.WithDebugHTTP(flagParams.Debug),
	)
	// ////////////////////////// ADMIN
	log.Info().Msg("Initializing router")
	// Create router for admin
	adminMux := http.NewServeMux()
	// ///////////////////////// UNAUTHENTICATED CONTENT
	// Admin: login only if local auth is enabled
	if flagParams.Service.Auth != config.AuthNone && flagParams.Service.Auth != config.AuthSAML {
		// login
		adminMux.HandleFunc("GET "+loginPath, handlersAdmin.LoginHandler)
		adminMux.HandleFunc("POST "+loginPath, handlersAdmin.LoginPOSTHandler)
		adminMux.HandleFunc("GET "+logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loginPath, http.StatusFound)
		})
	}
	// Admin: health of service
	adminMux.HandleFunc("GET "+healthPath, handlersAdmin.HealthHandler)
	// Admin: error
	adminMux.HandleFunc("GET "+errorPath, handlersAdmin.ErrorHandler)
	// Admin: forbidden
	adminMux.HandleFunc("GET "+forbiddenPath, handlersAdmin.ForbiddenHandler)
	// Admin: favicon
	adminMux.HandleFunc("GET "+faviconPath, handlersAdmin.FaviconHandler)
	// Admin: static
	adminMux.Handle("GET /static/", http.StripPrefix("/static", http.FileServer(http.Dir(flagParams.Admin.StaticDir))))
	// Admin: background image
	adminMux.HandleFunc("GET /background-image", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, flagParams.Admin.BackgroundImage)
	})
	// ///////////////////////// AUTHENTICATED CONTENT
	// Admin: branding image
	adminMux.Handle(
		"GET /branding-image",
		handlerAuthCheck(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.ServeFile(w, r, flagParams.Admin.BrandingImage)
			}),
			flagParams.Service.Auth,
		),
	)
	// Admin: paginated JSON data for environments
	adminMux.Handle(
		"GET /paginated-json/environment/{env}/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONEnvironmentPagingHandler), flagParams.Service.Auth))
	// Admin: JSON data for logs
	adminMux.Handle(
		"GET /json/logs/{type}/{env}/{uuid}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONLogsHandler), flagParams.Service.Auth))
	// Admin: JSON data for query logs
	adminMux.Handle(
		"GET /json/query/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryLogsHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"GET /json-download/query/{env}/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONDownloadQueryLogsHandler), flagParams.Service.Auth))
	// Admin: JSON data for sidebar stats
	adminMux.Handle(
		"GET /json/stats/{target}/{identifier}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONStatsHandler), flagParams.Service.Auth))
	// Admin: JSON data for tags
	adminMux.Handle(
		"GET /json/tags",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONTagsHandler), flagParams.Service.Auth))
	// Admin: JSON data for node search (UUID/hostname) - for Select2 AJAX
	adminMux.Handle(
		"GET /json/nodes/search",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONNodeSearchHandler), flagParams.Service.Auth))
	// Admin: JSON data for audit logs
	if flagParams.Service.AuditLog {
		adminMux.Handle(
			"GET /json/audit-logs",
			handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONAuditLogHandler), flagParams.Service.Auth))
	}
	// Admin: table for environments
	adminMux.Handle(
		"GET /environment/{env}/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvironmentHandler), flagParams.Service.Auth))
	// Admin: root
	adminMux.Handle(
		"GET /",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.RootHandler), flagParams.Service.Auth))
	// Admin: node view
	adminMux.Handle(
		"GET /node/{uuid}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeHandler), flagParams.Service.Auth))
	// Admin: multi node action
	adminMux.Handle(
		"POST /node/actions",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.NodeActionsPOSTHandler), flagParams.Service.Auth))
	// Admin: run queries
	adminMux.Handle(
		"GET /query/{env}/run",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /query/{env}/run",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryRunPOSTHandler), flagParams.Service.Auth))
	// Admin: list queries
	adminMux.Handle(
		"GET /query/{env}/list",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryListGETHandler), flagParams.Service.Auth))
	// Admin: saved queries
	adminMux.Handle(
		"GET /query/{env}/saved",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.SavedQueriesGETHandler), flagParams.Service.Auth))
	// Admin: query actions
	adminMux.Handle(
		"POST /query/{env}/actions",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryActionsPOSTHandler), flagParams.Service.Auth))
	// Admin: query JSON
	adminMux.Handle(
		"GET /query/{env}/json/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONQueryHandler), flagParams.Service.Auth))
	// Admin: query logs
	adminMux.Handle(
		"GET /query/{env}/logs/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.QueryLogsHandler), flagParams.Service.Auth))
	// Admin: carve files
	adminMux.Handle(
		"GET /carves/{env}/run",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /carves/{env}/run",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesRunPOSTHandler), flagParams.Service.Auth))
	// Admin: list carves
	adminMux.Handle(
		"GET /carves/{env}/list",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesListGETHandler), flagParams.Service.Auth))
	// Admin: carves actions
	adminMux.Handle(
		"POST /carves/{env}/actions",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesActionsPOSTHandler), flagParams.Service.Auth))
	// Admin: carves JSON
	adminMux.Handle(
		"GET /carves/{env}/json/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.JSONCarvesHandler), flagParams.Service.Auth))
	// Admin: carves details
	adminMux.Handle(
		"GET /carves/{env}/details/{name}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDetailsHandler), flagParams.Service.Auth))
	// Admin: carves download
	adminMux.Handle(
		"GET /carves/{env}/download/{sessionid}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.CarvesDownloadHandler), flagParams.Service.Auth))
	// Admin: nodes configuration
	adminMux.Handle(
		"GET /conf/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /conf/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.ConfPOSTHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /intervals/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.IntervalsPOSTHandler), flagParams.Service.Auth))
	// Admin: nodes enroll
	adminMux.Handle(
		"GET /enroll/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /enroll/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollPOSTHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"GET /enroll/{env}/download/{target}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnrollDownloadHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /expiration/{env}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.ExpirationPOSTHandler), flagParams.Service.Auth))
	// Admin: server settings
	adminMux.Handle(
		"GET /settings/{service}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /settings/{service}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.SettingsPOSTHandler), flagParams.Service.Auth))
	// Admin: manage environments
	adminMux.Handle(
		"GET /environments",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /environments",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EnvsPOSTHandler), flagParams.Service.Auth))
	// Admin: manage users
	adminMux.Handle(
		"GET /users",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /users",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.UsersPOSTHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"GET /users/permissions/{username}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /users/permissions/{username}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.PermissionsPOSTHandler), flagParams.Service.Auth))
	// Admin: manage tags
	adminMux.Handle(
		"GET /tags",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /tags",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagsPOSTHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /tags/nodes",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.TagNodesPOSTHandler), flagParams.Service.Auth))
	// Admin: manage tokens
	adminMux.Handle(
		"GET /tokens/{username}",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /tokens/{username}/refresh",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.TokensPOSTHandler), flagParams.Service.Auth))
	// Admin: edit profile
	adminMux.Handle(
		"GET /profile",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfileGETHandler), flagParams.Service.Auth))
	adminMux.Handle(
		"POST /profile",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.EditProfilePOSTHandler), flagParams.Service.Auth))
	// Admin: audit logs
	if flagParams.Service.AuditLog {
		adminMux.Handle(
			"GET /audit-logs",
			handlerAuthCheck(http.HandlerFunc(handlersAdmin.AuditLogsGETHandler), flagParams.Service.Auth))
	}
	// Admin: dashboard and search bar
	adminMux.Handle(
		"GET /dashboard",
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.DashboardGETHandler), flagParams.Service.Auth))
	// Admin: logout
	adminMux.Handle(
		"POST "+logoutPath,
		handlerAuthCheck(http.HandlerFunc(handlersAdmin.LogoutPOSTHandler), flagParams.Service.Auth))
	// SAML ACS
	if flagParams.Service.Auth == config.AuthSAML {
		adminMux.Handle("GET /saml/acs", samlMiddleware)
		adminMux.Handle("POST /saml/acs", samlMiddleware)
		adminMux.Handle("GET /saml/metadata", samlMiddleware)
		adminMux.Handle("POST /saml/metadata", samlMiddleware)
		adminMux.HandleFunc("GET "+loginPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LoginURL, http.StatusFound)
		})
		adminMux.HandleFunc("GET "+logoutPath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, samlConfig.LogoutURL, http.StatusFound)
		})
	}
	// Launch HTTP server for admin
	serviceListener := flagParams.Service.Listener + ":" + strconv.Itoa(flagParams.Service.Port)
	if flagParams.TLS.Termination {
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
			Handler:      adminMux,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
		}
		log.Info().Msgf("%s v%s - HTTPS listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := srv.ListenAndServeTLS(flagParams.TLS.CertificateFile, flagParams.TLS.KeyFile); err != nil {
			log.Fatal().Msgf("ListenAndServeTLS: %v", err)
		}
	} else {
		log.Info().Msgf("%s v%s - HTTP listening %s", serviceName, buildVersion, serviceListener)
		log.Info().Msgf("%s - commit=%s - build date=%s", serviceName, buildCommit, buildDate)
		if err := http.ListenAndServe(serviceListener, adminMux); err != nil {
			log.Fatal().Msgf("ListenAndServe: %v", err)
		}
	}
}

// Action to run when no flags are provided to run checks and prepare data
func cliAction(ctx context.Context, cmd *cli.Command) error {
	// Load configuration if external YAML config file is used
	if flagParams.ConfigFlag {
		serviceConfiguration, err = loadYAMLConfiguration(flagParams.ServiceConfigFile)
		if err != nil {
			return fmt.Errorf("error loading %s - %w", flagParams.ServiceConfigFile, err)
		}
		flagParams = loadedYAMLToServiceParams(serviceConfiguration, flagParams.ServiceConfigFile)
	}
	// Load osquery tables JSON file
	osqueryTables, err = loadOsqueryTables(flagParams.Osquery.TablesFile)
	if err != nil {
		return fmt.Errorf("failed to load osquery tables - %w", err)
	}
	return nil
}

func initializeLoggers(cfg config.YAMLConfigurationService) {
	// Set the log level
	switch strings.ToLower(cfg.LogLevel) {
	case config.LogLevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case config.LogLevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case config.LogLevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case config.LogLevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	// Set the log format
	switch strings.ToLower(cfg.LogFormat) {
	case config.LogFormatJSON:
		log.Logger = log.With().Caller().Logger()
	case config.LogFormatConsole:
		zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
			return filepath.Base(file) + ":" + strconv.Itoa(line)
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: logging.LoggerTimeFormat}).With().Caller().Logger()
	default:
		log.Logger = log.With().Caller().Logger()
	}
}

func main() {
	// Initiate CLI and parse arguments
	app = &cli.Command{
		Name:        serviceName,
		Usage:       appDescription,
		Version:     buildVersion,
		Description: appDescription,
		Flags: append(flags, &cli.BoolFlag{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Print version information",
			Action: func(ctx context.Context, cmd *cli.Command, b bool) error {
				if b {
					fmt.Printf("%s version=%s commit=%s date=%s\n", serviceName, buildVersion, buildCommit, buildDate)
					os.Exit(0)
				}
				return nil
			},
		}),
		HideVersion: true,
		Commands: []*cli.Command{
			{
				Name: "help",
				Action: func(ctx context.Context, cmd *cli.Command) error {
					cli.ShowAppHelpAndExit(cmd, 2)
					return nil
				},
			},
			{
				Name:    "config-validate",
				Aliases: []string{"config-verify"},
				Usage:   "Validate YAML configuration file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Usage:   "Path to the YAML configuration file to validate",
						Value:   "config/" + config.ServiceAdmin + ".yml",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					file := cmd.String("file")
					if file == "" {
						return fmt.Errorf("no configuration file provided")
					}
					_, err := loadYAMLConfiguration(file)
					if err != nil {
						return fmt.Errorf("❌ YAML configuration %s is invalid: %w", file, err)
					}
					fmt.Printf("✅ YAML configuration %s is valid.\n", file)
					return nil
				},
			},
			{
				Name:  "config-generate",
				Usage: "Generate an example configuration file using the current flag values",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "file",
						Aliases: []string{"f"},
						Value:   "config/" + config.ServiceAdmin + ".yml",
						Usage:   "File path to write the generated configuration",
					},
					&cli.BoolFlag{
						Name:    "force",
						Aliases: []string{"F"},
						Usage:   "Overwrite the output file if it already exists",
						Value:   false,
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					file := cmd.String("file")
					if err := config.GenerateAdminConfigFile(file, flagParams, cmd.Bool("force")); err != nil {
						return err
					}
					fmt.Printf("Example configuration written to %s.\n", file)
					return nil
				},
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if err := cliAction(ctx, cmd); err != nil {
				return err
			}
			// Initialize service logger
			initializeLoggers(*flagParams.Service)
			// Service starts!
			osctrlAdminService()
			return nil
		},
	}
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("app.Run error: %s", err.Error())
		os.Exit(1)
	}
}
