package config

import "time"

// S3Logger to hold all S3 configuration values
type S3Logger struct {
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	AccessKey       string `yaml:"accessKey"`
	SecretAccessKey string `yaml:"secretAccessKey"`
}

// S3Carver to hold all S3 configuration values
type S3Carver struct {
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	AccessKey       string `yaml:"accessKey"`
	SecretAccessKey string `yaml:"secretAccessKey"`
}

// LocalCarver to hold all local carver configuration values
type LocalCarver struct {
	CarvesDir string `yaml:"carvesDir"`
}

// KinesisLogger to hold all Kinesis configuration values
type KinesisLogger struct {
	Stream          string `yaml:"stream"`
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"`
	AccessKeyID     string `yaml:"accessKey"`
	SecretAccessKey string `yaml:"secretKey"`
	SessionToken    string `yaml:"sessionToken"`
}

type KafkaSASLConfigurations struct {
	Mechanism string `yaml:"mechanism"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
}

// KafkaLogger to hold all Kafka configuration values
type KafkaLogger struct {
	BootstrapServer   string                  `yaml:"bootstrapServers"`
	SSLCALocation     string                  `yaml:"sslCALocation"`
	ConnectionTimeout time.Duration           `yaml:"connectionTimeout"`
	SASL              KafkaSASLConfigurations `yaml:"sasl"`
	Topic             string                  `yaml:"topic"`
}

// GraylogLogger to hold all graylog configuration values
type GraylogLogger struct {
	URL     string `yaml:"url"`
	Host    string `yaml:"host"`
	Queries string `yaml:"queries"`
	Status  string `yaml:"status"`
	Results string `yaml:"results"`
}

// ElasticLogger to hold all elastic configuration values
type ElasticLogger struct {
	Host           string `yaml:"host"`
	Port           string `yaml:"port"`
	IndexPrefix    string `yaml:"indexPrefix"`
	DateSeparator  string `yaml:"dateSeparator"`  // Expected is . for YYYY.MM.DD
	IndexSeparator string `yaml:"indexSeparator"` // Expected is - for prefix-YYYY.MM.DD
}

// SplunkLogger to hold all splunk configuration values
type SplunkLogger struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
	Host  string `yaml:"host"`
	Index string `yaml:"index"`
}

// LogstashLogger to hold all logstash configuration values
type LogstashLogger struct {
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Path     string `yaml:"path"`
}

// LocalLogger to hold all local logger configuration values
type LocalLogger struct {
	FilePath string `yaml:"filePath"`
	// Maximum size in megabytes of the log file before it gets rotated
	MaxSize int `yaml:"maxSize"`
	// Maximum number of old log files to retain
	MaxBackups int `yaml:"maxBackups"`
	// Maximum number of days to retain old log files based on the timestamp encoded in their filename
	MaxAge int `yaml:"maxAge"`
	// If the rotated log files should be compressed using gzip
	Compress bool `yaml:"compress"`
}
