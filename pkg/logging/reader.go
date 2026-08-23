package logging

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/types"
)

// LogReader is the read-side abstraction over status / result / query logs.
//
// The historical implementation reads the `osquery_status_data`,
// `osquery_result_data` and `osquery_query_data` tables from the GORM DB
// (see dbLogReader). When the TLS logger is configured to ship logs to S3,
// those tables are empty — the data lives in S3 objects instead — and
// s3LogReader (see s3_reader.go) is wired in so the API/console/file
// explorer can still surface logs to the frontend.
//
// The interface intentionally mirrors the *read* functions the API and
// the console/file-explorer managers already use, so a handler does not
// care whether the backing store is the DB or S3.
type LogReader interface {
	// NodeLogs returns recent log entries for a single node (status or
	// result), ordered by created_at DESC. since is exclusive; empty means
	// no lower bound. limit is clamped to [1,1000] by the caller. search
	// is an optional case-insensitive substring filter against the row's
	// human-readable columns (best-effort for S3). severity is an optional
	// filter for status logs only (osquery severity integers: 0=info,
	// 1=warning, 2=error); "" or -1 means "no severity filter". Ignored
	// for result logs.
	NodeLogs(logType, env, uuid string, since time.Time, limit int, search string, severity string) ([]map[string]any, error)

	// QueryResults returns rows of query result data (one per node) for a
	// single query name, ordered by created_at ASC. env is the environment
	// UUID/name used to scope the read (the DB reader ignores it; the S3
	// reader uses it as the key prefix). Pagination is 1-indexed; pageSize
	// clamped to [1,1000]. Returns the page items, the total matching
	// count, and any error.
	QueryResults(env, name string, since time.Time, page, pageSize int) ([]map[string]any, int64, error)

	// StreamQueryResults invokes fn for each row of query result data for
	// `name`, ordered by created_at ASC. env scopes the read (DB reader
	// ignores it; S3 reader uses it as the key prefix). Rows are streamed
	// so memory stays bounded — used by the CSV exporter and the
	// console/file-explorer result decoders. fn may return an error to
	// stop iteration.
	StreamQueryResults(env, name string, fn func(OsqueryQueryData) error) error
}

// dbLogReader is the historical implementation backed by the GORM DB.
type dbLogReader struct {
	db *gorm.DB
}

// NewDBLogReader returns a LogReader backed by the given GORM DB.
func NewDBLogReader(db *gorm.DB) LogReader {
	return &dbLogReader{db: db}
}

func (r *dbLogReader) NodeLogs(logType, env, uuid string, since time.Time, limit int, search string, severity string) ([]map[string]any, error) {
	return GetNodeLogs(r.db, logType, env, uuid, since, limit, search, severity)
}

func (r *dbLogReader) QueryResults(env, name string, since time.Time, page, pageSize int) ([]map[string]any, int64, error) {
	return GetQueryResults(r.db, name, since, page, pageSize)
}

func (r *dbLogReader) StreamQueryResults(env, name string, fn func(OsqueryQueryData) error) error {
	return StreamQueryResults(r.db, name, fn)
}

// normalizeLogType maps the public "status"/"result" strings to the S3
// key prefix used by the TLS write path. It returns an error for any
// other value so a misrouted handler fails closed rather than silently
// listing the wrong prefix.
func normalizeLogType(logType string) (string, error) {
	switch logType {
	case types.StatusLog, types.ResultLog:
		return logType, nil
	default:
		return "", fmt.Errorf("invalid log type: %s", logType)
	}
}

// upperUUID normalizes a node UUID the way the DB writer does
// (OsqueryStatusData.UUID is stored upper-cased) so the S3 reader can
// match keys written with the original case-insensitive host identifier.
func upperUUID(uuid string) string {
	return strings.ToUpper(uuid)
}
