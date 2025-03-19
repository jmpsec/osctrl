package config

import "time"

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

// JSONConfigurationTLS to hold TLS service configuration values
type JSONConfigurationTLS struct {
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
}

type JSONConfigurationTLSWriter struct {
	// BatchWriter configuration: it need be refactored to a separate struct
	WriterBatchSize  int           `json:"writerBatchSize"`
	WriterTimeout    time.Duration `json:"writerTimeout"`
	WriterBufferSize int           `json:"writerBufferSize"`
}

// JSONConfigurationAdmin to hold admin service configuration values
type JSONConfigurationAdmin struct {
	Listener   string `json:"listener"`
	Port       string `json:"port"`
	LogLevel   string `json:"logLevel"`
	LogFormat  string `json:"logFormat"`
	Host       string `json:"host"`
	Auth       string `json:"auth"`
	Logger     string `json:"logger"`
	Carver     string `json:"carver"`
	SessionKey string `json:"sessionKey"`
}

// JSONConfigurationAPI to hold API service configuration values
type JSONConfigurationAPI struct {
	Listener  string `json:"listener"`
	Port      string `json:"port"`
	LogLevel  string `json:"logLevel"`
	LogFormat string `json:"logFormat"`
	Host      string `json:"host"`
	Auth      string `json:"auth"`
	Carver    string `json:"carver"`
}

// JSONConfigurationHeaders to keep all headers details for auth
type JSONConfigurationHeaders struct {
	TrustedPrefix     string `json:"trustedPrefix"`
	AdminGroup        string `json:"adminGroup"`
	UserGroup         string `json:"userGroup"`
	Email             string `json:"email"`
	UserName          string `json:"userName"`
	FirstName         string `json:"firstName"`
	LastName          string `json:"lastName"`
	DisplayName       string `json:"displayName"`
	DistinguishedName string `json:"distinguishedName"`
	Groups            string `json:"groups"`
	DefaultEnv        string `json:"defaultEnv"`
}

// JSONConfigurationJWT to hold all JWT configuration values
type JSONConfigurationJWT struct {
	JWTSecret     string `json:"jwtSecret"`
	HoursToExpire int    `json:"hoursToExpire"`
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
