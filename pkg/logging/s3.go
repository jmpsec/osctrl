package logging

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	osctrl_config "github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// LoggerS3 will be used to log data using S3
type LoggerS3 struct {
	S3Config  osctrl_config.S3Configuration
	AWSConfig aws.Config
	Client    *s3.Client
	Uploader  *manager.Uploader
	Enabled   bool
	Debug     bool
}

// CreateLoggerS3 to initialize the logger
func CreateLoggerS3(s3Config osctrl_config.S3Configuration) (*LoggerS3, error) {
	ctx := context.Background()
	creds := credentials.NewStaticCredentialsProvider(s3Config.AccessKey, s3Config.SecretAccessKey, "")
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithCredentialsProvider(creds), config.WithRegion(s3Config.Region),
	)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client)
	l := &LoggerS3{
		S3Config:  s3Config,
		AWSConfig: cfg,
		Client:    client,
		Uploader:  uploader,
		Enabled:   true,
		Debug:     false,
	}
	return l, nil
}

// CreateLoggerS3File to initialize the logger with a filename
func CreateLoggerS3File(s3File string) (*LoggerS3, error) {
	s3Config, err := LoadS3(s3File)
	if err != nil {
		return nil, err
	}
	return CreateLoggerS3(s3Config)
}

// LoadS3 - Function to load the S3 configuration from JSON file
func LoadS3(file string) (osctrl_config.S3Configuration, error) {
	var _s3Cfg osctrl_config.S3Configuration
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return _s3Cfg, err
	}
	cfgRaw := viper.Sub(osctrl_config.LoggingS3)
	if cfgRaw == nil {
		return _s3Cfg, fmt.Errorf("JSON key %s not found in %s", osctrl_config.LoggingS3, file)
	}
	if err := cfgRaw.Unmarshal(&_s3Cfg); err != nil {
		return _s3Cfg, err
	}
	// No errors!
	return _s3Cfg, nil
}

// Settings - Function to prepare settings for the logger
func (logS3 *LoggerS3) Settings(mgr *settings.Settings) {
	log.Info().Msg("No s3 logging settings")
}

// Send - Function that sends JSON logs to S3
func (logS3 *LoggerS3) Send(logType string, data []byte, environment, uuid string, debug bool) {
	ctx := context.Background()
	if debug {
		log.Debug().Msgf("Sending %d bytes to S3 for %s - %s", len(data), environment, uuid)
	}
	ptrContentLength := int64(len(data))
	result, err := logS3.Uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(logS3.S3Config.Bucket),
		Key:           aws.String(environment + "/" + logType + "/" + uuid + ":" + strconv.FormatInt(time.Now().UnixMilli(), 10) + ".json"),
		Body:          bytes.NewBuffer(data),
		ContentLength: &ptrContentLength,
		ContentType:   aws.String(http.DetectContentType(data)),
	})
	if err != nil {
		log.Err(err).Msg("Error sending data to s3")
	}
	if debug {
		log.Debug().Msgf("S3 Upload %+v", result)
	}
}
