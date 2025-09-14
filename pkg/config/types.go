package config

import (
	"time"
)

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

// JSONConfigurationService to hold the service configuration values
type JSONConfigurationService struct {
	Listener        string `json:"listener"`
	Port            string `json:"port"`
	LogLevel        string `json:"logLevel"`
	LogFormat       string `json:"logFormat"`
	MetricsListener string `json:"metricsListener"`
	MetricsPort     string `json:"metricsPort"`
	MetricsEnabled  bool   `json:"metricsEnabled"`
	Host            string `json:"host"`
	Auth            string `json:"auth"`
	Logger          string `json:"logger"`
	Carver          string `json:"carver"`
	SessionKey      string `json:"sessionKey"`
}

// TLSConfiguration to hold osctrl-tls configuration values
type TLSConfiguration struct {
	Service     YAMLConfigurationService `mapstructure:"service"`
	DB          YAMLConfigurationDB      `mapstructure:"db"`
	BatchWriter YAMLConfigurationWriter  `mapstructure:"batchWriter"`
	Redis       YAMLConfigurationRedis   `mapstructure:"redis"`
	Osquery     YAMLConfigurationOsquery `mapstructure:"osquery"`
	Osctrld     YAMLConfigurationOsctrld `mapstructure:"osctrld"`
	Metrics     YAMLConfigurationMetrics `mapstructure:"metrics"`
	TLS         YAMLConfigurationTLS     `mapstructure:"tls"`
	Logger      YAMLConfigurationLogger  `mapstructure:"logger"`
	Carver      YAMLConfigurationCarver  `mapstructure:"carver"`
	Debug       YAMLConfigurationDebug   `mapstructure:"debug"`
}

// AdminConfiguration to hold osctrl-admin configuration values
type AdminConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	Osquery YAMLConfigurationOsquery `mapstructure:"osquery"`
	Osctrld YAMLConfigurationOsctrld `mapstructure:"osctrld"`
	JWT     YAMLConfigurationJWT     `mapstructure:"jwt"`
	TLS     YAMLConfigurationTLS     `mapstructure:"tls"`
	Logger  YAMLConfigurationLogger  `mapstructure:"logger"`
	Carver  YAMLConfigurationCarver  `mapstructure:"carver"`
	Debug   YAMLConfigurationDebug   `mapstructure:"debug"`
}

// APIConfiguration to hold osctrl-api configuration values
type APIConfiguration struct {
	Service YAMLConfigurationService `mapstructure:"service"`
	DB      YAMLConfigurationDB      `mapstructure:"db"`
	Redis   YAMLConfigurationRedis   `mapstructure:"redis"`
	JWT     YAMLConfigurationJWT     `mapstructure:"jwt"`
	TLS     YAMLConfigurationTLS     `mapstructure:"tls"`
	Debug   YAMLConfigurationDebug   `mapstructure:"debug"`
}

// YAMLConfigurationService to hold the service configuration values
type YAMLConfigurationService struct {
	Listener  string `yaml:"listener"`
	Port      string `yaml:"port"`
	LogLevel  string `yaml:"logLevel"`
	LogFormat string `yaml:"logFormat"`
	Host      string `yaml:"host"`
	Auth      string `yaml:"auth"`
}

// YAMLConfigurationDB to hold all backend configuration values
type YAMLConfigurationDB struct {
	Type            string `yaml:"type"` // Database type: postgres, mysql, sqlite
	Host            string `yaml:"host"`
	Port            string `yaml:"port"`
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
	Port             string `yaml:"port"`
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
}

// YAMLConfigurationMetrics to hold the metrics configuration values
type YAMLConfigurationMetrics struct {
	Enabled  bool   `yaml:"enabled"`
	Listener string `yaml:"listener"`
	Port     string `yaml:"port"`
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
	Type         string `yaml:"type"`
	LoggerDBSame bool   `yaml:"loggerDBSame"`
	AlwaysLog    bool   `yaml:"alwaysLog"`
}

// YAMLConfigurationCarver to hold the carver configuration values
type YAMLConfigurationCarver struct {
	Type            string `yaml:"type"`
	CertificateFile string `yaml:"certificateFile"`
	KeyFile         string `yaml:"keyFile"`
}

// YAMLConfigurationDebug to hold the debug configuration values
type YAMLConfigurationDebug struct {
	EnableHTTP bool   `yaml:"enableHttp"`
	HTTPFile   string `yaml:"httpFile"`
	ShowBody   bool   `yaml:"showBody"`
}

// JSONConfigurationWriter to hold writer service configuration values
type JSONConfigurationWriter struct {
	// BatchWriter configuration: it need be refactored to a separate struct
	WriterBatchSize  int           `json:"writerBatchSize"`
	WriterTimeout    time.Duration `json:"writerTimeout"`
	WriterBufferSize int           `json:"writerBufferSize"`
}

// YAMLConfigurationWriter to hold the DB batch writer configuration values
type YAMLConfigurationWriter struct {
	// BatchWriter configuration: it need be refactored to a separate struct
	WriterBatchSize  int `yaml:"writerBatchSize"`
	WriterTimeout    int `yaml:"writerTimeout"`
	WriterBufferSize int `yaml:"writerBufferSize"`
}

// JSONConfigurationJWT to hold all JWT configuration values
type JSONConfigurationJWT struct {
	JWTSecret     string `json:"jwtSecret"`
	HoursToExpire int    `json:"hoursToExpire"`
}

// YAMLConfigurationJWT to hold all JWT configuration values
type YAMLConfigurationJWT struct {
	JWTSecret     string `yaml:"jwtSecret"`
	HoursToExpire int    `yaml:"hoursToExpire"`
}

// YAMLConfigurationSAML to keep all SAML details for auth
type YAMLConfigurationSAML struct {
	CertPath     string `yaml:"certpath"`
	KeyPath      string `yaml:"keypath"`
	MetaDataURL  string `yaml:"metadataurl"`
	RootURL      string `yaml:"rooturl"`
	LoginURL     string `yaml:"loginurl"`
	LogoutURL    string `yaml:"logouturl"`
	JITProvision bool   `yaml:"jitprovision"`
	SPInitiated  bool   `yaml:"spinitiated"`
}

// S3Configuration to hold all S3 configuration values
type S3Configuration struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKey       string `json:"accessKey"`
	SecretAccessKey string `json:"secretAccesKey"`
}

type KafkaSASLConfigurations struct {
	Mechanism string `json:"mechanism"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type KafkaConfiguration struct {
	BoostrapServer    string                  `json:"bootstrap_servers"`
	SSLCALocation     string                  `json:"ssl_ca_location"`
	ConnectionTimeout time.Duration           `json:"connection_timeout"`
	SASL              KafkaSASLConfigurations `json:"sasl"`
	Topic             string                  `json:"topic"`
}

// DebugHTTPConfiguration to hold all debug configuration values
type DebugHTTPConfiguration struct {
	Enabled  bool   `json:"enabled"`
	File     string `json:"file"`
	ShowBody bool   `json:"showBody"`
}

// OsctrldConfiguration to hold osctrld configuration values
type OsctrldConfiguration struct {
	Enabled bool `json:"enabled"`
}

// OsqueryConfiguration to hold osquery configuration values
type OsqueryConfiguration struct {
	Version    string `json:"version"`
	TablesFile string `json:"tablesFile"`
	Logger     bool   `json:"logger"`
	Config     bool   `json:"config"`
	Query      bool   `json:"query"`
	Carve      bool   `json:"carve"`
}
