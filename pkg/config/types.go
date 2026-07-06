package config

import (
	"time"
)

const YAMLConfigType = "yaml"
const YAMLDBType = "db"

// Types of services
const (
	ServiceTLS   string = "tls"
	ServiceAdmin string = "admin"
	ServiceAPI   string = "api"
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

// TLSConfiguration to hold osctrl-tls configuration values
type TLSConfiguration struct {
	Service         YAMLConfigurationService   `mapstructure:"service"`
	DB              YAMLConfigurationDB        `mapstructure:"db"`
	BatchWriter     YAMLConfigurationWriter    `mapstructure:"batchWriter"`
	Redis           YAMLConfigurationRedis     `mapstructure:"redis"`
	Osquery         YAMLConfigurationOsquery   `mapstructure:"osquery"`
	ConfigEndpoints YAMLConfigurationEndpoints `mapstructure:"configEndpoints"`
	Osctrld         YAMLConfigurationOsctrld   `mapstructure:"osctrld"`
	Metrics         YAMLConfigurationMetrics   `mapstructure:"metrics"`
	TLS             YAMLConfigurationTLS       `mapstructure:"tls"`
	Logger          YAMLConfigurationLogger    `mapstructure:"logger"`
	Carver          YAMLConfigurationCarver    `mapstructure:"carver"`
	Debug           YAMLConfigurationDebug     `mapstructure:"debug"`
}

// AdminConfiguration to hold osctrl-admin configuration values
type AdminConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	Osquery YAMLConfigurationOsquery `mapstructure:"osquery"`
	Osctrld YAMLConfigurationOsctrld `mapstructure:"osctrld"`
	SAML    YAMLConfigurationSAML    `mapstructure:"saml"`
	OIDC    YAMLConfigurationOIDC    `mapstructure:"oidc"`
	JWT     YAMLConfigurationJWT     `mapstructure:"jwt"`
	TLS     YAMLConfigurationTLS     `mapstructure:"tls"`
	Logger  YAMLConfigurationLogger  `mapstructure:"logger"`
	Carver  YAMLConfigurationCarver  `mapstructure:"carver"`
	Admin   YAMLConfigurationAdmin   `mapstructure:"admin"`
	Debug   YAMLConfigurationDebug   `mapstructure:"debug"`
}

// APIConfiguration to hold osctrl-api configuration values
type APIConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	Osquery YAMLConfigurationOsquery `mapstructure:"osquery"`
	JWT     YAMLConfigurationJWT     `mapstructure:"jwt"`
	TLS     YAMLConfigurationTLS     `mapstructure:"tls"`
	Logger  YAMLConfigurationLogger  `mapstructure:"logger"`
	Carver  YAMLConfigurationCarver  `mapstructure:"carver"`
	Debug   YAMLConfigurationDebug   `mapstructure:"debug"`
}

// YAMLConfigurationService to hold the service configuration values
type YAMLConfigurationService struct {
	Listener  string `yaml:"listener"`
	Port      int    `yaml:"port"`
	LogLevel  string `yaml:"logLevel"`
	LogFormat string `yaml:"logFormat"`
	Host      string `yaml:"host"`
	Auth      string `yaml:"auth"`
	AuditLog  bool   `yaml:"auditLog"`
	// TrustedProxies is a comma-separated list of CIDRs whose
	// X-Real-IP / X-Forwarded-For headers utils.GetIP will honor.
	// Default empty → forwarding headers are ignored and the
	// connection's RemoteAddr is used.
	TrustedProxies string `yaml:"trustedProxies"`
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
	Host             string `yaml:"host"`
	Port             int    `yaml:"port"`
	Password         string `yaml:"password"`
	ConnectionString string `yaml:"connectionString"`
	DB               int    `yaml:"db"`
	ConnRetry        int    `yaml:"connRetry"`
}

// YAMLConfigurationOsquery to hold the osquery configuration values
type YAMLConfigurationOsquery struct {
	Version    string `yaml:"version"`
	TablesFile string `yaml:"tablesFile"`
	Logger     bool   `yaml:"logger"`
	Config     bool   `yaml:"config"`
	Query      bool   `yaml:"query"`
	Carve      bool   `yaml:"carve"`
	ReadOnly   bool   `yaml:"readOnly"`
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

// YAMLConfigurationAdmin to hold admin UI specific configuration values
type YAMLConfigurationAdmin struct {
	SessionKey      string `yaml:"sessionKey"`
	StaticDir       string `yaml:"staticDir"`
	StaticOffline   bool   `yaml:"staticOffline"`
	TemplatesDir    string `yaml:"templatesDir"`
	BrandingImage   string `yaml:"brandingImage"`
	BackgroundImage string `yaml:"backgroundImage"`
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
	// Defaults false. The legacy osctrl-admin ignores this field
	// (it uses --auth=saml instead) so adding it does not affect
	// existing operator deployments.
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
	// Defaults false. legacy osctrl-admin ignores this field (it
	// uses --auth=oidc instead) so adding it does not affect any
	// existing operator deployment.
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
}
