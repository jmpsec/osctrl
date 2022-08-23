package logging

import (
	"log"
	"strings"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// LoggerS3 will be used to log data using S3
type LoggerS3 struct {
	Configuration types.S3Configuration
	Uploader      *s3manager.Uploader
	Enabled       bool
}

// CreateLoggerS3 to initialize the logger
func CreateLoggerS3(config types.S3Configuration) (*LoggerS3, error) {
	s := session.New(&aws.Config{
		Region:      aws.String(config.Region),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
	})
	l := &LoggerS3{
		Configuration: config,
		Uploader:      s3manager.NewUploader(s),
		Enabled:       true,
	}
	return l, nil
}

// CreateLoggerS3File to initialize the logger with a filename
func CreateLoggerS3File(s3File string) (*LoggerS3, error) {
	config, err := LoadS3(s3File)
	if err != nil {
		return nil, err
	}
	return CreateLoggerS3(config)
}

// LoadS3 - Function to load the S3 configuration from JSON file
func LoadS3(file string) (types.S3Configuration, error) {
	var _s3Cfg types.S3Configuration
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return _s3Cfg, err
	}
	cfgRaw := viper.Sub(settings.LoggingSplunk)
	if err := cfgRaw.Unmarshal(&_s3Cfg); err != nil {
		return _s3Cfg, err
	}
	// No errors!
	return _s3Cfg, nil
}

// Settings - Function to prepare settings for the logger
func (logS3 *LoggerS3) Settings(mgr *settings.Settings) {
	log.Printf("No s3 logging settings\n")
}

// Send - Function that sends JSON logs to S3
func (logS3 *LoggerS3) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("DebugService: Sending %d bytes to S3 for %s - %s", len(data), environment, uuid)
	}
	reader := strings.NewReader(string(data))
	uploadOutput, err := logS3.Uploader.Upload(&s3manager.UploadInput{
		Bucket: &logS3.Configuration.Bucket,
		Key:    aws.String(logType + ":" + environment + ":" + uuid),
		Body:   reader,
	})
	if err != nil {
		log.Printf("Error sending data to s3 %s", err)
	}
	if debug {
		log.Printf("DebugService: S3 Upload %+v", uploadOutput)
	}
}
