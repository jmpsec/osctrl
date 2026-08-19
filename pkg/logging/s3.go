package logging

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"time"

	osctrl_config "github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// LoggerS3 will be used to log data using S3
type LoggerS3 struct {
	S3Config  osctrl_config.S3Logger
	AWSConfig aws.Config
	Client    *s3.Client
	Enabled   bool
	Debug     bool
}

// CreateLoggerS3 to initialize the logger
func CreateLoggerS3(s3Config *osctrl_config.S3Logger) (*LoggerS3, error) {
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
	l := &LoggerS3{
		S3Config:  *s3Config,
		AWSConfig: cfg,
		Client:    client,
		Enabled:   true,
		Debug:     false,
	}
	return l, nil
}

// Settings - Function to prepare settings for the logger
func (logS3 *LoggerS3) Settings(mgr *settings.Settings) {
	log.Info().Msg("No s3 logging settings")
}

// Close releases resources held by the S3 logger. The AWS SDK v2
// s3.Client has no explicit Close; its HTTP transport pool is
// garbage-collected. This is a no-op kept for interface compliance.
func (logS3 *LoggerS3) Close() error { return nil }

// Send - Function that sends JSON logs to S3
func (logS3 *LoggerS3) Send(logType string, data []byte, environment, uuid string, debug bool) {
	ctx := context.Background()
	if debug {
		log.Debug().Msgf("Sending %d bytes to S3 for %s - %s", len(data), environment, uuid)
	}
	ptrContentLength := int64(len(data))
	result, err := logS3.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(logS3.S3Config.Bucket),
		Key:           aws.String(s3LogKey(environment, logType, uuid, time.Now())),
		Body:          bytes.NewReader(data),
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

// s3LogKey returns the S3 object key for a status/result log. The UUID is
// a path segment (not part of the filename) so the reader can list a
// single node's objects with a prefix filter. Exported so the reader and
// writer share the exact same layout.
//
// Key layout: {env}/{logType}/{uuid}/{ts}.json
func s3LogKey(environment, logType, uuid string, ts time.Time) string {
	return environment + "/" + logType + "/" + uuid + "/" + strconv.FormatInt(ts.UnixMilli(), 10) + ".json"
}

// Query - Function that sends JSON on-demand query result logs to S3.
//
// The S3 key embeds the query `name` as a path segment so the reader can
// list by query name with a prefix filter — without it, the reader would
// have to list every query object in the environment and decode each body
// to find the ones matching `name`, which is catastrophically slow on a
// busy bucket.
//
// Key layout: {env}/query/{name}/{uuid}/{ts}.json
//
// The body is the same QueryWriteData JSON the DB logger would have
// stored, so the reader can decode it back into OsqueryQueryData rows.
func (logS3 *LoggerS3) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	ctx := context.Background()
	if debug {
		log.Debug().Msgf("Sending %d bytes to S3 query %s for %s - %s", len(data), name, environment, uuid)
	}
	ptrContentLength := int64(len(data))
	result, err := logS3.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(logS3.S3Config.Bucket),
		Key:           aws.String(s3QueryKey(environment, name, uuid, time.Now())),
		Body:          bytes.NewReader(data),
		ContentLength: &ptrContentLength,
		ContentType:   aws.String(http.DetectContentType(data)),
	})
	if err != nil {
		log.Err(err).Msg("Error sending query data to s3")
	}
	if debug {
		log.Debug().Msgf("S3 Upload %+v", result)
	}
}

// s3QueryKey returns the S3 object key for a query result log. Exported
// so the reader and writer share the exact same layout.
//
// Key layout: {env}/query/{name}/{uuid}/{ts}.json
func s3QueryKey(environment, name, uuid string, ts time.Time) string {
	return environment + "/query/" + name + "/" + uuid + "/" + strconv.FormatInt(ts.UnixMilli(), 10) + ".json"
}
