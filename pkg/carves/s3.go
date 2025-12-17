package carves

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	osctrl_config "github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"

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
	// DownloadLinkExpiration in minutes to expire download links
	DownloadLinkExpiration = 5
)

// CarverS3 will be used to carve files using S3 as destination
type CarverS3 struct {
	S3Config  osctrl_config.S3Carver
	AWSConfig aws.Config
	Client    *s3.Client
	Uploader  *manager.Uploader
	Enabled   bool
	Debug     bool
}

// CreateCarverS3 to initialize the carver
func CreateCarverS3(s3Config osctrl_config.S3Carver) (*CarverS3, error) {
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

// Settings - Function to prepare settings for the logger
func (carveS3 *CarverS3) Settings(mgr *settings.Settings) {
	log.Info().Msg("No s3 logging settings")
}

// Upload - Function that sends data from carves to S3
func (carveS3 *CarverS3) Upload(block CarvedBlock, uuid, data string) error {
	ctx := context.Background()
	if carveS3.Debug {
		log.Debug().Msgf("Sending %d bytes to S3 for %s - %s", block.Size, block.Environment, uuid)
	}
	// Decode before upload
	toUpload, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("error decoding data - %w", err)
	}
	ptrContentLength := int64(len(toUpload))
	uploadOutput, err := carveS3.Uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(carveS3.S3Config.Bucket),
		Key:           aws.String(GenerateS3Key(block.Environment, uuid, block.SessionID, block.BlockID)),
		Body:          bytes.NewBuffer(toUpload),
		ContentLength: &ptrContentLength,
		ContentType:   aws.String(http.DetectContentType(toUpload)),
	})
	if err != nil {
		return fmt.Errorf("error sending data to s3 - %w", err)
	}
	if carveS3.Debug {
		log.Debug().Msgf("S3 Upload %+v", uploadOutput)
	}
	return nil
}

// Concatenate - Function to concatenate a file that have been already uploaded in s3
func (carveS3 *CarverS3) Concatenate(key string, destKey string, part int, uploadid *string) (*string, error) {
	ctx := context.Background()
	ptrPartNumber := int32(part)
	partOutput, err := carveS3.Client.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
		Bucket:     &carveS3.S3Config.Bucket,
		CopySource: aws.String(url.QueryEscape(carveS3.S3Config.Bucket + "/" + key)),
		PartNumber: &ptrPartNumber,
		Key:        aws.String(destKey),
		UploadId:   uploadid,
	})
	if err != nil {
		return nil, fmt.Errorf("UploadPartCopy - %s - %w", key, err)
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
	uploadOutput, err := carveS3.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &carveS3.S3Config.Bucket,
		Key:    aws.String(fkey),
	})
	if err != nil {
		return nil, fmt.Errorf("CreateMultipartUpload - %w", err)
	}
	if uploadOutput != nil && uploadOutput.UploadId != nil {
		if *uploadOutput.UploadId == "" {
			return nil, fmt.Errorf("empty UploadId")
		}
	}
	var parts []awsTypes.CompletedPart
	for _, b := range blocks {
		etag, err := carveS3.Concatenate(S3URLtoKey(b.Data, carveS3.S3Config.Bucket), fkey, b.BlockID+1, uploadOutput.UploadId)
		if err != nil {
			return nil, fmt.Errorf("error concatenating - %w", err)
		}
		ptrPartNumber := int32(b.BlockID + 1)
		p := awsTypes.CompletedPart{
			ETag:       etag,
			PartNumber: &ptrPartNumber,
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("error concatenating - %w", err)
	}
	// We finally complete the multipart upload.
	multiOutput, err := carveS3.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &carveS3.S3Config.Bucket,
		Key:      aws.String(GenerateS3File(carve.Environment, carve.UUID, carve.SessionID, carve.Path)),
		UploadId: uploadOutput.UploadId,
		MultipartUpload: &awsTypes.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CompleteMultipartUpload - %w", err)
	}
	if carveS3.Debug {
		log.Debug().Msgf("S3 Archived %s [%d bytes] - %s", res.File, res.Size, *multiOutput.Key)
	}
	return res, nil
}

// Download - Function to download an archived carve from s3
func (carveS3 *CarverS3) Download(carve CarvedFile) (io.WriterAt, error) {
	ctx := context.Background()
	if carveS3.Debug {
		log.Debug().Msgf("Downloading %s from S3", carve.ArchivePath)
	}
	downloader := manager.NewDownloader(carveS3.Client)
	var fileReader io.WriterAt
	downloadedBytes, err := downloader.Download(ctx, fileReader, &s3.GetObjectInput{
		Bucket: aws.String(carveS3.S3Config.Bucket),
		Key:    aws.String(S3URLtoKey(carve.ArchivePath, carveS3.S3Config.Bucket)),
	})
	// Forcing sequential downloads so we can skip the offset from io.WriterAt
	downloader.Concurrency = 1
	if err != nil {
		return nil, fmt.Errorf("Download - %w", err)
	}
	if carveS3.Debug {
		log.Debug().Msgf("S3 Downloaded %s [%d bytes]", carve.ArchivePath, downloadedBytes)
	}
	return fileReader, nil
}

// GetDownloadLink - Function to generate a pre-signed link to download directly from s3
func (carveS3 *CarverS3) GetDownloadLink(carve CarvedFile) (string, error) {
	ctx := context.Background()
	if carveS3.Debug {
		log.Debug().Msgf("Downloading link %s from S3", carve.ArchivePath)
	}
	preClient := s3.NewPresignClient(carveS3.Client)
	lnk, err := preClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(carveS3.S3Config.Bucket),
		Key:    aws.String(S3URLtoKey(carve.ArchivePath, carveS3.S3Config.Bucket)),
	}, s3.WithPresignExpires(DownloadLinkExpiration*time.Minute))
	if err != nil {
		return "", fmt.Errorf("PresignGetObject - %w", err)
	}
	return lnk.URL, nil
}
