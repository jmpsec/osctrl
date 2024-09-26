package logging

import (
	"fmt"

	"github.com/jmpsec/osctrl/settings"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
)

// KinesisConfiguration to hold all Kinesis configuration values
type KinesisConfiguration struct {
	Stream          string `json:"stream"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key"`
	SecretAccessKey string `json:"secret_key"`
	SessionToken    string `json:"session_token"`
}

// LoggerKinesis will be used to log data using Kinesis
type LoggerKinesis struct {
	Configuration KinesisConfiguration
	KinesisClient *kinesis.Kinesis
	Enabled       bool
}

// CreateLoggerKinesis to initialize the logger
func CreateLoggerKinesis(kinesisFile string) (*LoggerKinesis, error) {
	config, err := LoadKinesis(kinesisFile)
	if err != nil {
		return nil, err
	}
	s := session.New(&aws.Config{
		Region:      aws.String(config.Region),
		Endpoint:    aws.String(config.Endpoint),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, config.SessionToken),
	})
	kc := kinesis.New(s)
	streamName := aws.String(config.Stream)
	_, err = kc.DescribeStream(&kinesis.DescribeStreamInput{StreamName: streamName})
	if err != nil {
		return nil, fmt.Errorf("DescribeStream: %v", err)
	}
	l := &LoggerKinesis{
		Configuration: config,
		KinesisClient: kc,
		Enabled:       true,
	}
	return l, nil
}

// LoadKinesis - Function to load the Kinesis configuration from JSON file
func LoadKinesis(file string) (KinesisConfiguration, error) {
	var _kinesisCfg KinesisConfiguration
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return _kinesisCfg, err
	}
	cfgRaw := viper.Sub(settings.LoggingSplunk)
	if err := cfgRaw.Unmarshal(&_kinesisCfg); err != nil {
		return _kinesisCfg, err
	}
	// No errors!
	return _kinesisCfg, nil
}

// Settings - Function to prepare settings for the logger
func (logSK *LoggerKinesis) Settings(mgr *settings.Settings) {
	log.Info().Msg("No kinesis logging settings")
}

// Send - Function that sends JSON logs to Splunk HTTP Event Collector
func (logSK *LoggerKinesis) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("DebugService: Sending %d bytes to Kinesis for %s - %s", len(data), environment, uuid)
	}
	streamName := aws.String(logSK.Configuration.Stream)
	putOutput, err := logSK.KinesisClient.PutRecord(&kinesis.PutRecordInput{
		Data:         []byte(data),
		StreamName:   streamName,
		PartitionKey: aws.String(logType + ":" + environment + ":" + uuid),
	})
	if err != nil {
		log.Err(err).Msg("Error sending kinesis stream")
	}
	if debug {
		log.Debug().Msgf("DebugService: PutRecordOutput %s", putOutput.String())
	}
}
