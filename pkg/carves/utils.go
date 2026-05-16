package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/jmpsec/osctrl/pkg/utils"
)

const (
	// S3proto to be used as s3 URL
	S3proto = "s3://"
	// S3URL to format the s3 URL
	S3URL = S3proto + "%s/%s"
	// S3Key to format the s3 key for a block
	S3Key = "%s:%s:%s:%d"
	// S3File to format the s3 key for a reconstructed file
	S3File = "%s:%s:%s:%s" + TarFileExtension
	// LocalFile to format the local file name
	LocalFile = "%s_%s_%s" + TarFileExtension
)

// Function to generate a carve block filename for s3
func GenerateS3Data(bucket, env, uuid, sessionid string, blockid int) string {
	return fmt.Sprintf(S3URL, bucket, GenerateS3Key(env, uuid, sessionid, blockid))
}

// Function to generate a carve archived filename for s3
func GenerateS3Archive(bucket, env, uuid, sessionid, path string) string {
	return fmt.Sprintf(S3URL, bucket, GenerateS3File(env, uuid, sessionid, path))
}

// Function to generate the s3 key for a carve block
func GenerateS3Key(env, uuid, sessionid string, blockid int) string {
	return fmt.Sprintf(S3Key, env, uuid, sessionid, blockid)
}

// Function to generate the s3 file reconstructed from blocks
func GenerateS3File(env, uuid, sessionid, path string) string {
	return fmt.Sprintf(S3File, env, uuid, sessionid, path)
}

// Function to translate from a s3:// URL to just the key
func S3URLtoKey(s3url, bucket string) string {
	return strings.TrimPrefix(s3url, fmt.Sprintf(S3proto+"%s/", bucket))
}

// Function to generate a local file for carve archives
func GenerateArchiveName(carve CarvedFile) string {
	cPath := strings.ReplaceAll(strings.ReplaceAll(carve.Path, "/", "-"), "\\", "-")
	return fmt.Sprintf(LocalFile, carve.UUID, carve.SessionID, cPath)
}

// Function to check if data is compressed using zstd
// https://github.com/facebook/zstd
//
// Returns false on inputs shorter than the 4-byte zstd magic — callers
// may feed arbitrary node-controlled bytes, so the length check is the
// only thing preventing a slice-bounds panic that would crash the
// service.
func CheckCompressionRaw(data []byte) bool {
	if len(data) < len(CompressionHeader) {
		return false
	}
	return bytes.Equal(data[:len(CompressionHeader)], CompressionHeader)
}

// Function to check if a block data is compressed using zstd
// https://github.com/facebook/zstd
func CheckCompressionBlock(block CarvedBlock) (bool, error) {
	// Make sure this is the block 0
	if block.BlockID != 0 {
		return false, fmt.Errorf("block_id is not 0 (%d)", block.BlockID)
	}
	compressionCheck, err := base64.StdEncoding.DecodeString(block.Data)
	if err != nil {
		return false, fmt.Errorf("error decoding block %w", err)
	}
	return CheckCompressionRaw(compressionCheck), nil
}

// Helper to generate a random carve name
func GenCarveName() string {
	return "carve_" + utils.RandomForNames()
}

// validCarvePath restricts the characters that can appear in a carve
// path. The carve string is concatenated into the osquery SQL that
// every targeted node executes; without this gate a CarveLevel
// operator could inject arbitrary osquery (e.g. `'; SELECT 1; --`) and
// pivot from "exfil this path" to "run any SELECT against your nodes".
//
// The character class covers realistic carve targets across the three
// platforms: absolute POSIX paths (Linux/macOS), Windows paths with
// backslashes and drive letters, and glob wildcards (* and ?). It
// explicitly excludes single quote, semicolon, and comment markers.
var validCarvePath = regexp.MustCompile(`^[/A-Za-z0-9._\-\\:*?]+$`)

// ValidCarvePath reports whether s is a safe value to splice into
// GenCarveQuery. Callers MUST verify before calling GenCarveQuery —
// the result is interpolated directly into SQL.
func ValidCarvePath(s string) bool {
	if s == "" {
		return false
	}
	return validCarvePath.MatchString(s)
}

// Helper to generate the carve query.
//
// `file` is interpolated into the SQL string verbatim. The caller MUST
// have validated it via ValidCarvePath beforehand — passing an
// unvalidated user-controlled value here lets the requesting operator
// run arbitrary osquery on every targeted host, which is well beyond
// the "carve a file" capability the endpoint advertises.
func GenCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + file + "';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + file + "';"
}
