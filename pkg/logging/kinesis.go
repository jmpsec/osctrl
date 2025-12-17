package logging

import (
	"context"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
)

// LoggerKinesis will be used to log data using Kinesis
type LoggerKinesis struct {
	Configuration config.KinesisLogger
	KinesisClient *kinesis.Client
	Enabled       bool
}

// CreateLoggerKinesis to initialize the logger
func CreateLoggerKinesis(cfg *config.KinesisLogger) (*LoggerKinesis, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" || cfg.SessionToken != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken),
			))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	var kinesisOpts []func(*kinesis.Options)
	if cfg.Endpoint != "" {
		endpoint := cfg.Endpoint
		kinesisOpts = append(kinesisOpts, func(o *kinesis.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	kc := kinesis.NewFromConfig(awsCfg, kinesisOpts...)

	if _, err := kc.DescribeStream(context.Background(), &kinesis.DescribeStreamInput{
		StreamName: aws.String(cfg.Stream),
	}); err != nil {
		return nil, fmt.Errorf("DescribeStream: %w", err)
	}

	return &LoggerKinesis{
		Configuration: *cfg,
		KinesisClient: kc,
		Enabled:       true,
	}, nil
}

// Settings - Function to prepare settings for the logger
func (logSK *LoggerKinesis) Settings(mgr *settings.Settings) {
	log.Info().Msg("No kinesis logging settings")
}

// Send - Function that sends JSON logs to Splunk HTTP Event Collector
func (logSK *LoggerKinesis) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("Sending %d bytes to Kinesis for %s - %s", len(data), environment, uuid)
	}
	streamName := aws.String(logSK.Configuration.Stream)
	putOutput, err := logSK.KinesisClient.PutRecord(context.Background(), &kinesis.PutRecordInput{
		Data:         data,
		StreamName:   streamName,
		PartitionKey: aws.String(logType + ":" + environment + ":" + uuid),
	})
	if err != nil {
		log.Err(err).Msg("Error sending kinesis stream")
		return
	}
	if debug {
		log.Debug().Msgf("PutRecordOutput %+v", putOutput)
	}
}
