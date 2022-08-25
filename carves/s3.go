package carves

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	// MaxUploadRetries to define how many times retry to upload
	MaxUploadRetries = 3
	// MaxChunkSize to define max size for each part. AWS defines 5MB max per part
	MaxChunkSize = int64(5 * 1024 * 1024)
)

// CarverS3 will be used to carve files using S3 as destination
type CarverS3 struct {
	S3Config  types.S3Configuration
	AWSConfig aws.Config
	Client    *s3.Client
	Uploader  *manager.Uploader
	Enabled   bool
	Debug     bool
}

// CreateCarverS3File to initialize the carver
func CreateCarverS3File(s3File string) (*CarverS3, error) {
	config, err := LoadS3(s3File)
	if err != nil {
		return nil, err
	}
	return CreateCarverS3(config)
}

// CreateCarverS3 to initialize the carver
func CreateCarverS3(s3Config types.S3Configuration) (*CarverS3, error) {
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
	l := &CarverS3{
		S3Config:  s3Config,
		AWSConfig: cfg,
		Client:    client,
		Uploader:  uploader,
		Enabled:   true,
		Debug:     true,
	}
	return l, nil
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
	cfgRaw := viper.Sub(settings.LoggingS3)
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

// Upload - Function that sends data from carves to S3
func (carveS3 *CarverS3) Upload(block CarvedBlock, uuid, data string) error {
	ctx := context.Background()
	if carveS3.Debug {
		log.Printf("DebugService: Sending %d bytes to S3 for %s - %s", block.Size, block.Environment, uuid)
	}
	// Decode before upload
	toUpload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("error decoding data - %v", err)
	}
	uploadOutput, err := carveS3.Uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(carveS3.S3Config.Bucket),
		Key:           aws.String(GenerateS3Key(block.Environment, uuid, block.SessionID, block.BlockID)),
		Body:          bytes.NewBuffer(toUpload),
		ContentLength: int64(len(toUpload)),
		ContentType:   aws.String(http.DetectContentType(toUpload)),
	})
	if err != nil {
		return fmt.Errorf("error sending data to s3 - %s", err)
	}
	if carveS3.Debug {
		log.Printf("DebugService: S3 Upload %+v", uploadOutput)
	}
	return nil
}

// Concatenate - Function to concatenate a file that have been already uploaded in s3
func (carveS3 *CarverS3) Concatenate(key string, destKey string, part int, uploadid *string) (*string, error) {
	ctx := context.Background()
	partOutput, err := carveS3.Client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
		Bucket:     &carveS3.S3Config.Bucket,
		CopySource: aws.String(url.QueryEscape(carveS3.S3Config.Bucket + "/" + key)),
		PartNumber: int32(part),
		Key:        aws.String(destKey),
		UploadId:   uploadid,
	})
	if err != nil {
		return nil, fmt.Errorf("error uploading part %s - %s", key, err)
	}
	return partOutput.CopyPartResult.ETag, nil
}

// Archive - Function to convert finalize a completed carve and create a file ready to download
func (carveS3 *CarverS3) Archive(carve CarvedFile, blocks []CarvedBlock) (*CarveResult, error) {
	ctx := context.Background()
	res := &CarveResult{
		Size: int64(carve.CarveSize),
		File: GenerateS3Archive(carveS3.S3Config.Bucket, carve.Environment, carve.UUID, carve.SessionID, carve.Path),
	}
	// Initiate a multipart upload
	fkey := GenerateS3File(carve.Environment, carve.UUID, carve.SessionID, carve.Path)
	output, err := carveS3.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &carveS3.S3Config.Bucket,
		Key:    aws.String(fkey),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating multipart upload - %s", err)
	}
	var parts []awsTypes.CompletedPart
	for i, b := range blocks {
		etag, err := carveS3.Concatenate(S3URLtoKey(b.Data, carveS3.S3Config.Bucket), fkey, i, output.UploadId)
		if err != nil {
			return nil, fmt.Errorf("error concatenating - %s", err)
		}
		p := awsTypes.CompletedPart{
			ETag:       etag,
			PartNumber: int32(i),
		}
		parts = append(parts, p)
	}
	if err != nil {
		return nil, fmt.Errorf("error sending data to s3 - %s", err)
	}
	// We finally complete the multipart upload.
	_, err = carveS3.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &carveS3.S3Config.Bucket,
		Key:      aws.String(GenerateS3File(carve.Environment, carve.UUID, carve.SessionID, carve.Path)),
		UploadId: output.UploadId,
		MultipartUpload: &awsTypes.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if carveS3.Debug {
		log.Printf("DebugService: S3 Archived %s [%d bytes]", res.File, res.Size)
	}
	return res, nil
}
