package config

import (
	"time"
)

const YAMLConfigType = "yaml"
const YAMLDBType = "db"

// Types of services
const (
	ServiceTLS string = "tls"
	ServiceAPI string = "api"
)

const (
	// log levels
	LogLevelDebug string = "debug"
	LogLevelInfo  string = "info"
	LogLevelWarn  string = "warn"
	LogLevelError string = "error"
	// log formats
	LogFormatConsole string = "console"
	LogFormatJSON    string = "json"
)

// Types of authentication
const (
	AuthNone  string = "none"
	AuthJSON  string = "json"
	AuthDB    string = "db"
	AuthSAML  string = "saml"
	AuthJWT   string = "jwt"
	AuthOAuth string = "oauth"
	AuthOIDC  string = "oidc"
)

// Types of logging
const (
	LoggingNone     string = "none"
	LoggingStdout   string = "stdout"
	LoggingFile     string = "file"
	LoggingDB       string = "db"
	LoggingGraylog  string = "graylog"
	LoggingSplunk   string = "splunk"
	LoggingLogstash string = "logstash"
	LoggingKinesis  string = "kinesis"
	LoggingS3       string = "s3"
	LoggingKafka    string = "kafka"
	LoggingElastic  string = "elastic"
)

// Types of carver
const (
	CarverLocal string = "local"
	CarverDB    string = "db"
	CarverS3    string = "s3"
)

// Types of backend
const (
	DBTypePostgres string = "postgres"
	DBTypeMySQL    string = "mysql"
	DBTypeSQLite   string = "sqlite"
)

// TLSConfiguration to hold osctrl-tls configuration values. Required sections
// (service, db, redis) are value types; optional sections are pointers so a
// minimal YAML file can omit them and the service falls back to DB-stored or
// zero-valued defaults.
type TLSConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	// Optional sections — nil when absent from the YAML file. The service
	// boot code and serviceconfig.Resolve handle nil gracefully.
	BatchWriter     *YAMLConfigurationWriter     `mapstructure:"batchWriter"`
	Osquery         *YAMLConfigurationOsquery    `mapstructure:"osquery"`
	ConfigEndpoints *YAMLConfigurationEndpoints  `mapstructure:"configEndpoints"`
	Osctrld         *YAMLConfigurationOsctrld    `mapstructure:"osctrld"`
	Metrics         *YAMLConfigurationMetrics    `mapstructure:"metrics"`
	TLS             *YAMLConfigurationTLS        `mapstructure:"tls"`
	Logger          *YAMLConfigurationLogger     `mapstructure:"logger"`
	Carver          *YAMLConfigurationCarver     `mapstructure:"carver"`
	Debug           *YAMLConfigurationDebug      `mapstructure:"debug"`
	RateLimits      *YAMLConfigurationRateLimits `mapstructure:"rateLimits"`
}

// APIConfiguration to hold osctrl-api configuration values. Required sections
// (service, db, redis) are value types; optional sections are pointers.
type APIConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	// Optional sections — nil when absent from the YAML file.
	Osquery    *YAMLConfigurationOsquery    `mapstructure:"osquery"`
	SAML       *YAMLConfigurationSAML       `mapstructure:"saml"`
	OIDC       *YAMLConfigurationOIDC       `mapstructure:"oidc"`
	JWT        *YAMLConfigurationJWT        `mapstructure:"jwt"`
	TLS        *YAMLConfigurationTLS        `mapstructure:"tls"`
	Logger     *YAMLConfigurationLogger     `mapstructure:"logger"`
	Carver     *YAMLConfigurationCarver     `mapstructure:"carver"`
	Debug      *YAMLConfigurationDebug      `mapstructure:"debug"`
	RateLimits *YAMLConfigurationRateLimits `mapstructure:"rateLimits"`
}

// YAMLConfigurationService to hold the service configuration values
type YAMLConfigurationService struct {
	Listener  string `yaml:"listener"`
	Port      int    `yaml:"port"`
	LogLevel  string `yaml:"logLevel"`
	LogFormat string `yaml:"logFormat"`
	Host      string `yaml:"host"`
	// GeoIPDBPath is the path to a MaxMind GeoLite2-Country .mmdb file.
	// When set, the API resolves node IP addresses to country codes and
	// includes them in the node API response. When empty (default), the
	// feature is disabled and no country codes are returned.
	GeoIPDBPath string `yaml:"geoipDBPath"`
	// PostureEnabled controls whether the security & compliance posture
	// system is active. When false (default), the entire posture
	// subsystem is disabled — no ingestion, no API endpoints.
	PostureEnabled bool `yaml:"postureEnabled"`
	// PostureQueryPrefix is the prefix that identifies scheduled queries
	// whose result logs are ingested as node posture data. Only used
	// when PostureEnabled is true.
	PostureQueryPrefix string `yaml:"postureQueryPrefix"`
	// ServiceConfigEnabled controls whether the service-config API and the
	// matching SPA section exist. It does not change how configuration is
	// loaded: every boot seeds the YAML sections into the database and
	// then resolves the stored values back over them, so the services
	// always read from the database rows. When false (default) none of the
	// /api/v1/service-config routes are registered and the SPA hides the
	// section — the rows can still be changed directly in the database, or
	// in the YAML file, and are picked up on the next restart. Consumed by
	// osctrl-api; osctrl-tls ignores it.
	ServiceConfigEnabled bool `yaml:"serviceConfigEnabled"`
	// LogSinksEnabled controls whether the log-sinks API and SPA section
	// exist. When false, the /api/v1/log-sinks routes are not registered
	// and the SPA hides the section. Independent of ServiceConfigEnabled.
	// Defaults to true (nil).
	LogSinksEnabled *bool `yaml:"logSinksEnabled"`
	// AuthProvidersEnabled controls whether the auth-providers API and
	// SPA section exist. When false, the /api/v1/auth-providers routes
	// are not registered and the SPA hides the section. Independent of
	// ServiceConfigEnabled. Defaults to true (nil).
	AuthProvidersEnabled *bool `yaml:"authProvidersEnabled"`
	// MFARequired makes a second authentication factor mandatory for
	// password logins. Users who have none are sent through enrollment at
	// their next login instead of being locked out. Service accounts are
	// exempt (they authenticate with a token, not interactively), and
	// federated logins are unaffected — the identity provider owns the
	// factor policy there.
	MFARequired bool `yaml:"mfaRequired"`
	// MFAIssuer is the label authenticator apps show next to the account.
	// Defaults to "osctrl" when empty.
	MFAIssuer string `yaml:"mfaIssuer"`
	// MFARPID is the WebAuthn Relying Party ID: the registrable domain
	// credentials are bound to, without scheme or port. Empty defaults to
	// Host. Changing it invalidates every registered credential.
	MFARPID string `yaml:"mfaRPID"`
	// MFAOrigins is the comma-separated list of origins the SPA is served
	// from, including scheme and any non-default port
	// ("https://osctrl.example.com"). Empty defaults to https://<Host>.
	// A browser refuses the ceremony if its origin is not in this list.
	MFAOrigins string `yaml:"mfaOrigins"`
	Auth       string `yaml:"auth"`
	AuditLog   bool   `yaml:"auditLog"`
	// TrustedProxies is a comma-separated list of CIDRs whose
	// X-Real-IP / X-Forwarded-For headers utils.GetIP will honor.
	// Default empty → forwarding headers are ignored and the
	// connection's RemoteAddr is used.
	TrustedProxies string `yaml:"trustedProxies"`
	// DBHealthCheck enables a background DB liveness monitor.
	// When true, the service pings the DB every DBHealthInterval
	// seconds and, after DBHealthThreshold consecutive failures,
	// switches EnvCache and SettingsCache into stale-serve mode
	// (serve cached entries on DB miss, extend TTLs) so osquery
	// nodes keep getting config/logs during a DB outage.
	DBHealthCheck     bool `yaml:"dbHealthCheck"`
	DBHealthInterval  int  `yaml:"dbHealthInterval"`
	DBHealthThreshold int  `yaml:"dbHealthThreshold"`
}

// YAMLConfigurationDB to hold all backend configuration values
type YAMLConfigurationDB struct {
	Type            string `yaml:"type"` // Database type: postgres, mysql, sqlite
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	Name            string `yaml:"name"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	SSLMode         string `yaml:"sslmode"` // For postgres
	MaxIdleConns    int    `yaml:"maxIdleConns"`
	MaxOpenConns    int    `yaml:"maxOpenConns"`
	ConnMaxLifetime int    `yaml:"connMaxLifetime"`
	ConnRetry       int    `yaml:"connRetry"`
	FilePath        string `yaml:"filePath"` // Used for SQLite
}

// YAMLConfigurationRedis to hold all redis configuration values
type YAMLConfigurationRedis struct {
	Host             string `yaml:"host" mapstructure:"host"`
	Port             int    `yaml:"port" mapstructure:"port"`
	Password         string `yaml:"password" mapstructure:"password"`
	ConnectionString string `yaml:"connectionString" mapstructure:"connectionString"`
	DB               int    `yaml:"db" mapstructure:"db"`
	ConnRetry        int    `yaml:"connRetry" mapstructure:"connRetry"`
}

// YAMLConfigurationOsquery to hold the osquery configuration values
type YAMLConfigurationOsquery struct {
	Version      string `yaml:"version"`
	TablesFile   string `yaml:"tablesFile"`
	Logger       bool   `yaml:"logger"`
	Config       bool   `yaml:"config"`
	Query        bool   `yaml:"query"`
	Carve        bool   `yaml:"carve"`
	Accelerated  bool   `yaml:"accelerated"`
	Console      bool   `yaml:"console"`
	FileExplorer bool   `yaml:"fileExplorer"`
	ReadOnly     bool   `yaml:"readOnly"`
}

// YAMLConfigurationEndpoints to hold the configuration endpoints that will receive osquery configuration updates
type YAMLConfigurationEndpoints []YAMLConfigurationEndpoint

// YAMLConfigurationEndpoint to hold each endpoint that will receive osquery configuration updates
type YAMLConfigurationEndpoint struct {
	Environment    string `yaml:"environment"`
	Secret         string `yaml:"secret"`
	IntegrityCheck bool   `yaml:"integrityCheck"`
}

// YAMLConfigurationMetrics to hold the metrics configuration values
type YAMLConfigurationMetrics struct {
	Enabled  bool   `yaml:"enabled"`
	Listener string `yaml:"listener"`
	Port     int    `yaml:"port"`
}

// YAMLConfigurationOsctrld to hold the osctrld configuration values
type YAMLConfigurationOsctrld struct {
	Enabled bool `yaml:"enabled"`
}

// YAMLConfigurationTLS to hold the TLS/SSL termination configuration values
type YAMLConfigurationTLS struct {
	Termination     bool   `yaml:"termination"`
	CertificateFile string `yaml:"certificateFile"`
	KeyFile         string `yaml:"keyFile"`
}

// YAMLConfigurationLogger to hold the logger configuration values
type YAMLConfigurationLogger struct {
	Type         string               `yaml:"type"`
	Types        []string             `yaml:"types" mapstructure:"types"`
	LoggerDBSame bool                 `yaml:"loggerDBSame"`
	AlwaysLog    bool                 `yaml:"alwaysLog"`
	DB           *YAMLConfigurationDB `mapstructure:"db"`
	S3           *S3Logger            `mapstructure:"s3"`
	Graylog      *GraylogLogger       `mapstructure:"graylog"`
	Elastic      *ElasticLogger       `mapstructure:"elastic"`
	Splunk       *SplunkLogger        `mapstructure:"splunk"`
	Logstash     *LogstashLogger      `mapstructure:"logstash"`
	Kinesis      *KinesisLogger       `mapstructure:"kinesis"`
	Kafka        *KafkaLogger         `mapstructure:"kafka"`
	Local        *LocalLogger         `mapstructure:"local"`
}

// YAMLConfigurationCarver to hold the carver configuration values
type YAMLConfigurationCarver struct {
	Type  string       `yaml:"type"`
	S3    *S3Carver    `mapstructure:"s3"`
	Local *LocalCarver `mapstructure:"local"`
}

// YAMLConfigurationDebug to hold the debug configuration values
type YAMLConfigurationDebug struct {
	EnableHTTP bool   `yaml:"enableHttp"`
	HTTPFile   string `yaml:"httpFile"`
	ShowBody   bool   `yaml:"showBody"`
	// TargetHostIdentifier, when non-empty, restricts the HTTP debug dump
	// to requests coming from the osquery node whose UUID (uppercase) or
	// enroll host_identifier matches this value (case-insensitive). When
	// empty, every request is dumped as long as EnableHTTP is true — the
	// legacy behavior. Endpoints that identify a node (enroll, config,
	// log, queryRead, queryWrite, carveInit) can match; pre-enroll /
	// no-node endpoints are skipped while a filter is set.
	TargetHostIdentifier string `yaml:"hostIdentifier"`
}

// YAMLConfigurationRateLimit holds one token-bucket rate limit.
type YAMLConfigurationRateLimit struct {
	Burst      int           `yaml:"burst" mapstructure:"burst"`
	Period     time.Duration `yaml:"period" mapstructure:"period"`
	EvictAfter time.Duration `yaml:"evictAfter" mapstructure:"evictAfter"`
	RetryAfter int           `yaml:"retryAfter" mapstructure:"retryAfter"`
	MaxBuckets int           `yaml:"maxBuckets" mapstructure:"maxBuckets"`
}

// YAMLConfigurationRateLimits holds service request-throttle settings.
type YAMLConfigurationRateLimits struct {
	Login              YAMLConfigurationRateLimit `yaml:"login" mapstructure:"login"`
	PreAuth            YAMLConfigurationRateLimit `yaml:"preAuth" mapstructure:"preAuth"`
	ServiceConfigApply YAMLConfigurationRateLimit `yaml:"serviceConfigApply" mapstructure:"serviceConfigApply"`
	Enroll             YAMLConfigurationRateLimit `yaml:"enroll" mapstructure:"enroll"`
}

// YAMLConfigurationWriter to hold the DB batch writer configuration values
type YAMLConfigurationWriter struct {
	// BatchWriter configuration: it need be refactored to a separate struct
	WriterBatchSize  int           `yaml:"writerBatchSize"`
	WriterTimeout    time.Duration `yaml:"writerTimeout"`
	WriterBufferSize int           `yaml:"writerBufferSize"`
}

// YAMLConfigurationJWT to hold all JWT configuration values
type YAMLConfigurationJWT struct {
	JWTSecret     string `yaml:"jwtSecret"`
	HoursToExpire int    `yaml:"hoursToExpire"`
}

// YAMLConfigurationSAML to keep all SAML details for auth
type YAMLConfigurationSAML struct {
	// Enabled gates the SAML federated-login surface on osctrl-api.
	// Defaults false.
	Enabled bool `yaml:"enabled"        mapstructure:"enabled"`
	// EntityID is the SP entity identifier — what the IdP knows us
	// by. Conventionally the metadata URL.
	EntityID string `yaml:"entityId"       mapstructure:"entityId"`
	// ACSURL is the Assertion Consumer Service URL — where the IdP
	// POSTs the SAMLResponse. Must match the value registered with
	// the IdP. Ends with /api/v1/auth/saml/acs.
	ACSURL       string `yaml:"acsUrl"         mapstructure:"acsUrl"`
	CertPath     string `yaml:"certPath"`
	KeyPath      string `yaml:"keyPath"`
	MetaDataURL  string `yaml:"metadataUrl"`
	RootURL      string `yaml:"rootUrl"`
	LoginURL     string `yaml:"loginUrl"`
	LogoutURL    string `yaml:"logoutUrl"       mapstructure:"logoutUrl"`
	JITProvision bool   `yaml:"jitProvision"   mapstructure:"jitProvision"`
	// LinkLocalAccounts lets a SAML identity claim an existing LOCAL
	// (password) account with the same username. Off by default: with it
	// on, whoever controls the IdP's username namespace can take over any
	// same-named local account, including admins.
	LinkLocalAccounts bool `yaml:"linkLocalAccounts" mapstructure:"linkLocalAccounts"`
	// UsernameAttribute names the SAML attribute (by Name or
	// FriendlyName) whose value becomes the osctrl username.
	// Empty means "use the NameID verbatim" — fine for Keycloak
	// where NameID is the username, but Auth0 typically emits an
	// emailAddress NameID format which fails our strict sanitizer,
	// so operators point this at "nickname" instead.
	UsernameAttribute string `yaml:"usernameAttribute" mapstructure:"usernameAttribute"`
	// SigningCertPath + SigningKeyPath are PEM file paths to the
	// SP's signing certificate + RSA private key. When BOTH are
	// set, the provider signs every outbound AuthnRequest with
	// RSA-SHA256 and advertises AuthnRequestsSigned="true" in SP
	// metadata. The IdP-side SAML client must be configured to
	// require client signatures and to trust this cert.
	SigningCertPath string `yaml:"signingCertPath" mapstructure:"signingCertPath"`
	SigningKeyPath  string `yaml:"signingKeyPath"  mapstructure:"signingKeyPath"`
	// ForceAuthn defaults true on osctrl-api. Setting it false lets
	// "Continue with SAML" silently re-authenticate against an
	// existing IdP SSO cookie, which most operators perceive as
	// "logout didn't work" — see auth_logout.go comment for the v1
	// rationale.
	ForceAuthn  bool `yaml:"forceAuthn"      mapstructure:"forceAuthn"`
	SPInitiated bool `yaml:"spInitiated"`
}

// YAMLConfigurationOIDC to keep all OIDC details for auth
type YAMLConfigurationOIDC struct {
	// Enabled gates the federated-login surface on osctrl-api.
	// Defaults false.
	Enabled        bool     `yaml:"enabled"        mapstructure:"enabled"`
	IssuerURL      string   `yaml:"issuerUrl"      mapstructure:"issuerUrl"`
	ClientID       string   `yaml:"clientId"       mapstructure:"clientId"`
	ClientSecret   string   `yaml:"clientSecret"   mapstructure:"clientSecret"`
	RedirectURL    string   `yaml:"redirectUrl"    mapstructure:"redirectUrl"`
	Scopes         []string `yaml:"scopes"         mapstructure:"scopes"`
	UsernameClaim  string   `yaml:"usernameClaim"  mapstructure:"usernameClaim"`
	GroupsClaim    string   `yaml:"groupsClaim"    mapstructure:"groupsClaim"`
	RequiredGroups []string `yaml:"requiredGroups" mapstructure:"requiredGroups"`
	JITProvision   bool     `yaml:"jitProvision"   mapstructure:"jitProvision"`
	UsePKCE        bool     `yaml:"usePKCE"        mapstructure:"usePKCE"`
	// LinkLocalAccounts lets an OIDC identity claim an existing LOCAL
	// (password) account with the same username. Off by default: with it
	// on, whoever controls the IdP's username namespace can take over any
	// same-named local account, including admins.
	LinkLocalAccounts bool `yaml:"linkLocalAccounts" mapstructure:"linkLocalAccounts"`
}
