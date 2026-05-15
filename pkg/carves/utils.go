package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
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

// escapeSQLString returns s with every single quote doubled, so the
// result is safe to interpolate inside a SQL string literal — osquery
// (SQLite) follows the standard rule that '' inside a literal is one
// literal quote, and there is no backslash escape to consider. This
// is the SQL-injection defense for GenCarveQuery: a path containing
// `'; DROP TABLE x; --` becomes `''; DROP TABLE x; --`, which the
// parser sees as the contents of the string literal — there is no
// way to escape the surrounding quotes.
func escapeSQLString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// escapeLikePattern returns s escaped for a SQL LIKE pattern, using
// `\` as the escape character. Caller MUST emit the resulting query
// with `ESCAPE '\'`. Order matters: escape the escape char first.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// globToLike maps the carve-style globs `*` and `?` to LIKE wildcards
// `%` and `_`, after escaping any literal LIKE metacharacters the
// path may already contain, then escaping SQL string quotes. The
// caller MUST emit the resulting pattern with `ESCAPE '\'`.
//
// Order matters: LIKE-escape (which inserts `\`) runs before the
// glob mapping (so existing `%`/`_` stay literal), and SQL-quote
// escaping runs last so doubled quotes are not themselves escaped
// by the LIKE pass.
func globToLike(s string) string {
	s = escapeLikePattern(s)
	s = strings.ReplaceAll(s, "*", "%")
	s = strings.ReplaceAll(s, "?", "_")
	s = escapeSQLString(s)
	return s
}

// GenCarveQuery builds the osquery SQL that selects matching `carves`
// rows on every targeted node. The carve `file` is treated as an
// untrusted SQL string literal: single quotes are doubled so a
// CarveLevel operator cannot break out of the literal to pivot from
// "carve this path" into arbitrary SELECTs (e.g. `'; SELECT 1; --`).
//
// In glob mode `*` and `?` map to LIKE wildcards `%` and `_`, with
// any pre-existing `%`, `_`, or `\` in the path escaped via `ESCAPE '\'`
// so they are treated as literals.
//
// Paths containing spaces (e.g. `C:\Program Files\...`,
// `/Library/Application Support/...`) and any UTF-8 characters are
// supported.
func GenCarveQuery(file string, glob bool) string {
	if glob {
		return "SELECT * FROM carves WHERE carve=1 AND path LIKE '" + globToLike(file) + "' ESCAPE '\\';"
	}
	return "SELECT * FROM carves WHERE carve=1 AND path = '" + escapeSQLString(file) + "';"
}
