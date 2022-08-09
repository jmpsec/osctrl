package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"

	"github.com/jmpsec/osctrl/settings"
	"github.com/spf13/viper"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	// MaxUploadRetries to define how many times retry to upload
	MaxUploadRetries = 3
	// MaxChunkSize to define max size for each part. AWS defines 5MB max per part
	MaxChunkSize = int64(5 * 1024 * 1024)
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
	Session       *session.Session
	Client        *s3.S3
	Uploader      *s3manager.Uploader
	Downloader    *s3manager.Downloader
	Enabled       bool
	Debug         bool
}

// CreateCarverS3 to initialize the carver
func CreateCarverS3(s3File string) (*CarverS3, error) {
	config, err := LoadS3(s3File)
	if err != nil {
		return nil, err
	}
	cfg := &aws.Config{
		Region:      aws.String(config.Region),
		Credentials: credentials.NewStaticCredentials(config.AccessKeyID, config.SecretAccessKey, ""),
	}
	s := session.New(cfg)
	l := &CarverS3{
		Configuration: config,
		Session:       s,
		Uploader:      s3manager.NewUploader(s),
		Downloader:    s3manager.NewDownloader(s),
		Client:        s3.New(s, cfg),
		Enabled:       true,
		Debug:         true,
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

// Upload - Function that sends data from carves to S3
func (carveS3 *CarverS3) Upload(block CarvedBlock, uuid, data string) error {
	if carveS3.Debug {
		log.Printf("DebugService: Sending %d bytes to S3 for %s - %s", block.Size, block.Environment, uuid)
	}
	// Decode before upload
	toUpload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("error decoding data - %v", err)
	}
	reader := bytes.NewReader(toUpload)
	uploadOutput, err := carveS3.Uploader.Upload(&s3manager.UploadInput{
		Bucket: &carveS3.Configuration.Bucket,
		Key:    aws.String(GenerateS3Key(block.Environment, uuid, block.SessionID, block.BlockID)),
		Body:   reader,
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
	partOutput, err := carveS3.Client.UploadPartCopy(&s3.UploadPartCopyInput{
		Bucket:     &carveS3.Configuration.Bucket,
		CopySource: aws.String(url.QueryEscape(carveS3.Configuration.Bucket + "/" + key)),
		PartNumber: aws.Int64(int64(part)),
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
	res := &CarveResult{
		Size: int64(carve.CarveSize),
		File: GenerateS3Archive(carveS3.Configuration.Bucket, carve.Environment, carve.UUID, carve.SessionID, carve.Path),
	}
	// Initiate a multipart upload
	fkey := GenerateS3File(carve.Environment, carve.UUID, carve.SessionID, carve.Path)
	output, err := carveS3.Client.CreateMultipartUpload(&s3.CreateMultipartUploadInput{
		Bucket: &carveS3.Configuration.Bucket,
		Key:    aws.String(fkey),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating multipart upload - %s", err)
	}
	var parts []*s3.CompletedPart
	for i, b := range blocks {
		etag, err := carveS3.Concatenate(S3URLtoKey(b.Data, carveS3.Configuration.Bucket), fkey, i, output.UploadId)
		if err != nil {
			return nil, fmt.Errorf("error concatenating - %s", err)
		}
		p := &s3.CompletedPart{
			ETag:       etag,
			PartNumber: aws.Int64(int64(i)),
		}
		parts = append(parts, p)
	}
	if err != nil {
		return nil, fmt.Errorf("error sending data to s3 - %s", err)
	}
	// We finally complete the multipart upload.
	_, err = carveS3.Client.CompleteMultipartUpload(&s3.CompleteMultipartUploadInput{
		Bucket:   &carveS3.Configuration.Bucket,
		Key:      aws.String(GenerateS3File(carve.Environment, carve.UUID, carve.SessionID, carve.Path)),
		UploadId: output.UploadId,
		MultipartUpload: &s3.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if carveS3.Debug {
		log.Printf("DebugService: S3 Archived %s [%d bytes]", res.File, res.Size)
	}
	return res, nil
}
