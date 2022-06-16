package carves

import (
	"log"
	"strings"

	"github.com/jmpsec/osctrl/settings"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

// S3Configuration to hold all S3 configuration values
type S3Configuration struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"access_key"`
	SecretAccessKey string `json:"secret_key"`
}

// CarverS3 will be used to carve files using S3 as destination
type CarverS3 struct {
	Configuration S3Configuration
	Uploader      *s3manager.Uploader
	Enabled       bool
}

// CreateCarverS3 to initialize the carver
func CreateCarverS3(s3File string) (*CarverS3, error) {
	config, err := LoadS3(s3File)
	if err != nil {
		return nil, err
	}
	s := session.New(&aws.Config{
		Region:      aws.String(config.Region),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
	})
	l := &CarverS3{
		Configuration: config,
		Uploader:      s3manager.NewUploader(s),
		Enabled:       true,
	}
	return l, nil
}

// LoadS3 - Function to load the S3 configuration from JSON file
func LoadS3(file string) (S3Configuration, error) {
	var _s3Cfg S3Configuration
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
func (carveS3 *CarverS3) Settings(mgr *settings.Settings) {
	log.Printf("No s3 logging settings\n")
}

// Send - Function that sends data from carves to S3
func (carveS3 *CarverS3) Upload(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("DebugService: Sending %d bytes to S3 for %s - %s", len(data), environment, uuid)
	}
	reader := strings.NewReader(string(data))
	uploadOutput, err := carveS3.Uploader.Upload(&s3manager.UploadInput{
		Bucket: &carveS3.Configuration.Bucket,
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
