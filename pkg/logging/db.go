package logging

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/dbutil"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// OsqueryResultData to log result data to database
type OsqueryResultData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Name        string
	Action      string
	Epoch       int64
	Columns     string
	Counter     int
}

// OsqueryStatusData to log status data to database
type OsqueryStatusData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Line        string
	Message     string
	Version     string
	Filename    string
	Severity    string
}

// OsqueryQueryData to log query data to database
type OsqueryQueryData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Name        string
	Data        string
	Status      int
}

// LoggerDB will be used to log data using a database
type LoggerDB struct {
	Database *backend.DBManager
	Enabled  bool
}

// CreateLoggerDB to initialize the logger without reading a config file
func CreateLoggerDBConfig(dbConfig *config.YAMLConfigurationDB) (*LoggerDB, error) {
	// Initialize backend
	backend, err := backend.CreateDBManager(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend - %w", err)
	}
	return CreateLoggerDB(backend)
}

// CreateLoggerDB to initialize the logger without reading a config file
func CreateLoggerDB(backend *backend.DBManager) (*LoggerDB, error) {
	l := &LoggerDB{
		Database: backend,
		Enabled:  true,
	}
	// table osquery_status_data
	if err := backend.Conn.AutoMigrate(&OsqueryStatusData{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (osquery_status_data): %v", err)
	}
	// table osquery_result_data
	if err := backend.Conn.AutoMigrate(&OsqueryResultData{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (osquery_result_data): %v", err)
	}
	// table osquery_query_data
	if err := backend.Conn.AutoMigrate(&OsqueryQueryData{}); err != nil {
		log.Fatal().Msgf("Failed to AutoMigrate table (osquery_query_data): %v", err)
	}
	return l, nil
}

// Settings - Function to prepare settings for the logger
func (logDB *LoggerDB) Settings(mgr *settings.Settings) {
	log.Info().Msg("Setting DB logging settings")
}

// Log - Function that sends JSON result/status/query logs to the configured DB
func (logDB *LoggerDB) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("Sending %d bytes to DB for %s - %s", len(data), environment, uuid)
	}
	switch logType {
	case types.StatusLog:
		logDB.Status(data, environment, uuid, debug)
	case types.ResultLog:
		logDB.Result(data, environment, uuid, debug)
	}
}

// Status - Function that sends JSON status logs to the configured DB
func (logDB *LoggerDB) Status(data []byte, environment, uuid string, debug bool) {
	// Parse JSON
	var logs []types.LogStatusData
	if err := json.Unmarshal(data, &logs); err != nil {
		log.Err(err).Msgf("error parsing logs %s %v", string(data), err)
	}
	// Iterate and insert in DB
	for _, l := range logs {
		entry := OsqueryStatusData{
			UUID:        strings.ToUpper(l.HostIdentifier),
			Environment: environment,
			Line:        strconv.Itoa(int(l.Line)),
			Message:     l.Message,
			Version:     l.Version,
			Filename:    l.Filename,
			Severity:    strconv.Itoa(int(l.Severity)),
		}
		if err := logDB.Database.Conn.Create(&entry).Error; err != nil {
			log.Err(err).Msg("Error creating status log entry")
		}
	}
}

// Result - Function that sends JSON result logs to the configured DB
func (logDB *LoggerDB) Result(data []byte, environment, uuid string, debug bool) {
	// Parse JSON
	logs, err := parseResultLogs(data)
	if err != nil {
		log.Err(err).Msgf("error parsing logs %s", string(data))
	}
	// Iterate and insert in DB
	for _, l := range logs {
		entry := OsqueryResultData{
			UUID:        strings.ToUpper(l.HostIdentifier),
			Environment: environment,
			Name:        l.Name,
			Action:      l.Action,
			Epoch:       l.Epoch,
			Columns:     string(l.Columns),
			Counter:     l.Counter,
		}
		if err := logDB.Database.Conn.Create(&entry).Error; err != nil {
			log.Err(err).Msg("Error creating result log entry")
		}
	}
}

// Query - Function that sends JSON query logs to the configured DB
func (logDB *LoggerDB) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	// Prepare data
	entry := OsqueryQueryData{
		UUID:        strings.ToUpper(uuid),
		Environment: environment,
		Name:        name,
		Data:        string(data),
		Status:      status,
	}
	// Insert in DB
	if err := logDB.Database.Conn.Create(&entry).Error; err != nil {
		log.Err(err).Msg("Error creating query log")
	}
}

// QueryLogs will retrieve all query logs
func (logDB *LoggerDB) QueryLogs(name string) ([]OsqueryQueryData, error) {
	var logs []OsqueryQueryData
	if err := logDB.Database.Conn.Where("name = ?", name).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// StatusLogs will retrieve all status logs
func (logDB *LoggerDB) StatusLogs(uuid, environment string, seconds int64) ([]OsqueryStatusData, error) {
	var logs []OsqueryStatusData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Conn.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Where("created_at < ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// StatusLogsLimit will retrieve a limited number of status logs
func (logDB *LoggerDB) StatusLogsLimit(uuid, environment string, limit int) ([]OsqueryStatusData, error) {
	var logs []OsqueryStatusData
	if err := logDB.Database.Conn.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Order("created_at desc").Limit(limit).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// ResultLogs will retrieve all result logs
func (logDB *LoggerDB) ResultLogs(uuid, environment string, seconds int64) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Conn.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Where("created_at < ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// ResultLogsLimit will retrieve a limited number of result logs
func (logDB *LoggerDB) ResultLogsLimit(uuid, environment string, limit int) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	if err := logDB.Database.Conn.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Order("created_at").Limit(limit).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// GetNodeLogs retrieves recent log entries for a single node (status or result).
// logType must be "status" or "result". Results are ordered by created_at DESC.
// If since is non-zero only entries created strictly after that time are returned.
// limit is clamped to [1, 1000].
//
// search is an optional free-text filter (substring, case-insensitive). It
// runs as a `LIKE` against the human-readable text columns of the row:
//   - status: line + message + filename
//   - result: name + action + columns (the serialized JSON of matched fields)
//
// Empty search disables the filter — same behavior as a missing param.
//
// The `LIKE` is unindexed today. If the result_data / status_data tables
// grow large enough to make this slow, an operator-side workaround is to
// narrow `since` first, which keeps the matched row count small.
func GetNodeLogs(db *gorm.DB, logType, env, uuid string, since time.Time, limit int, search string) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	uuid = strings.ToUpper(uuid)
	// Escape SQL LIKE wildcards in the user input so a literal '%' in a
	// pasted token doesn't match more than intended. GORM auto-escapes the
	// quote+backslash but not the wildcard metacharacters.
	likeNeedle := ""
	if search != "" {
		needle := strings.ReplaceAll(search, `\`, `\\`)
		needle = strings.ReplaceAll(needle, `%`, `\%`)
		needle = strings.ReplaceAll(needle, `_`, `\_`)
		likeNeedle = "%" + needle + "%"
	}

	var result []map[string]any

	switch logType {
	case types.StatusLog:
		var rows []OsqueryStatusData
		q := db.Where("uuid = ? AND environment = ?", uuid, env)
		if !since.IsZero() {
			q = q.Where("created_at > ?", since)
		}
		if likeNeedle != "" {
			// LOWER() so the search is case-insensitive. The needle is
			// already plain-text; lowercasing both sides handles UTF-8
			// only weakly (no Unicode case-folding) but is good enough
			// for the IR/incident use case which is mostly ASCII tokens.
			lowerNeedle := strings.ToLower(likeNeedle)
			q = q.Where(
				"LOWER(line) LIKE ? OR LOWER(message) LIKE ? OR LOWER(filename) LIKE ?",
				lowerNeedle, lowerNeedle, lowerNeedle,
			)
		}
		if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			result = append(result, map[string]any{
				"id":          r.ID,
				"created_at":  r.CreatedAt,
				"uuid":        r.UUID,
				"environment": r.Environment,
				"line":        r.Line,
				"message":     r.Message,
				"version":     r.Version,
				"filename":    r.Filename,
				"severity":    r.Severity,
			})
		}
	case types.ResultLog:
		var rows []OsqueryResultData
		q := db.Where("uuid = ? AND environment = ?", uuid, env)
		if !since.IsZero() {
			q = q.Where("created_at > ?", since)
		}
		if likeNeedle != "" {
			lowerNeedle := strings.ToLower(likeNeedle)
			q = q.Where(
				"LOWER(name) LIKE ? OR LOWER(action) LIKE ? OR LOWER(columns) LIKE ?",
				lowerNeedle, lowerNeedle, lowerNeedle,
			)
		}
		if err := q.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			result = append(result, map[string]any{
				"id":          r.ID,
				"created_at":  r.CreatedAt,
				"uuid":        r.UUID,
				"environment": r.Environment,
				"name":        r.Name,
				"action":      r.Action,
				"epoch":       r.Epoch,
				"columns":     r.Columns,
				"counter":     r.Counter,
			})
		}
	default:
		return nil, fmt.Errorf("invalid log type: %s", logType)
	}

	return result, nil
}

// GetNodeStatusTimestamps and GetNodeResultTimestamps return just the
// CreatedAt column for every status/result log row a given node has shipped
// since `since`. Used by the per-node activity heatmap so it can bucket on
// the API side without dragging the row bodies across the wire.
//
// Returning a slice of timestamps (rather than int64 epochs) keeps the
// downstream bucketing arithmetic in Go's time domain, which is what the
// rest of cmd/api/handlers/stats.go uses.
func GetNodeStatusTimestamps(db *gorm.DB, env, uuid string, since time.Time) ([]time.Time, error) {
	uuid = strings.ToUpper(uuid)
	var ts []time.Time
	err := db.Model(&OsqueryStatusData{}).
		Where("uuid = ? AND environment = ? AND created_at >= ?", uuid, env, since).
		Pluck("created_at", &ts).Error
	return ts, err
}

func GetNodeResultTimestamps(db *gorm.DB, env, uuid string, since time.Time) ([]time.Time, error) {
	uuid = strings.ToUpper(uuid)
	var ts []time.Time
	err := db.Model(&OsqueryResultData{}).
		Where("uuid = ? AND environment = ? AND created_at >= ?", uuid, env, since).
		Pluck("created_at", &ts).Error
	return ts, err
}

// GetNodeStatusBucketed returns per-bucket row counts for `uuid` in `env`
// since `since`, with buckets aligned to `bucketSeconds`. The SQL pushes the
// histogram into the database (one GROUP BY) instead of shipping every
// timestamp to the API process — orders of magnitude less wire traffic on
// chatty nodes.
func GetNodeStatusBucketed(db *gorm.DB, env, uuid string, since time.Time, bucketSeconds int) ([]dbutil.BucketedRow, error) {
	uuid = strings.ToUpper(uuid)
	expr := dbutil.BucketExpr(db, "created_at", bucketSeconds)
	var rows []dbutil.BucketedRow
	err := db.Model(&OsqueryStatusData{}).
		Select(expr+" AS bucket_start, COUNT(*) AS cnt").
		Where("uuid = ? AND environment = ? AND created_at >= ?", uuid, env, since).
		Group("bucket_start").
		Scan(&rows).Error
	return rows, err
}

// GetNodeResultBucketed mirrors GetNodeStatusBucketed for osquery_result_data.
func GetNodeResultBucketed(db *gorm.DB, env, uuid string, since time.Time, bucketSeconds int) ([]dbutil.BucketedRow, error) {
	uuid = strings.ToUpper(uuid)
	expr := dbutil.BucketExpr(db, "created_at", bucketSeconds)
	var rows []dbutil.BucketedRow
	err := db.Model(&OsqueryResultData{}).
		Select(expr+" AS bucket_start, COUNT(*) AS cnt").
		Where("uuid = ? AND environment = ? AND created_at >= ?", uuid, env, since).
		Group("bucket_start").
		Scan(&rows).Error
	return rows, err
}

// GetQueryResults retrieves rows of query result data (one per node) for a single query name.
// Results are ordered by created_at ASC (oldest first — query results are append-only).
// If since is non-zero only rows created strictly after that time are returned.
// page is 1-indexed; pageSize is clamped to [1, 1000]; pageSize <= 0 defaults to 100.
// Returns the page items, total matching rows, and any error.
func GetQueryResults(db *gorm.DB, name string, since time.Time, page, pageSize int) ([]map[string]any, int64, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	q := db.Model(&OsqueryQueryData{}).Where("name = ?", name)
	if !since.IsZero() {
		q = q.Where("created_at > ?", since)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []OsqueryQueryData
	if err := q.Order("created_at ASC").Offset(offset).Limit(pageSize).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, map[string]any{
			"id":          r.ID,
			"created_at":  r.CreatedAt,
			"uuid":        r.UUID,
			"environment": r.Environment,
			"name":        r.Name,
			"data":        r.Data,
			"status":      r.Status,
		})
	}
	return out, total, nil
}

// StreamQueryResults invokes fn for each row of query result data for `name`, ordered by created_at ASC.
// Rows are read via a cursor so memory usage stays bounded — used by the CSV exporter.
// fn may return an error to stop iteration; that error is returned by StreamQueryResults.
func StreamQueryResults(db *gorm.DB, name string, fn func(OsqueryQueryData) error) error {
	rows, err := db.Model(&OsqueryQueryData{}).Where("name = ?", name).Order("created_at ASC").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r OsqueryQueryData
		if err := db.ScanRows(rows, &r); err != nil {
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// CleanStatusLogs will delete old status logs
func (logDB *LoggerDB) CleanStatusLogs(environment string, seconds int64) error {
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Conn.Unscoped().Where("environment = ?", environment).Where("created_at < ?", minusSeconds).Delete(&OsqueryStatusData{}).Error; err != nil {
		return fmt.Errorf("CleanStatusLogs %w", err)
	}
	return nil
}

// CleanResultLogs will delete old status logs
func (logDB *LoggerDB) CleanResultLogs(environment string, seconds int64) error {
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Conn.Unscoped().Where("environment = ?", environment).Where("created_at < ?", minusSeconds).Delete(&OsqueryResultData{}).Error; err != nil {
		return fmt.Errorf("CleanResultLogs %w", err)
	}
	return nil
}

// CleanQueryLogs will delete old query logs
func (logDB *LoggerDB) CleanQueryLogs(entries int64) error {
	// TODO this would be better and simpler with foreign keys and delete cascade
	// Find queries to delete with OFFSET
	var oldQueries []queries.DistributedQuery
	logDB.Database.Conn.Offset(int(entries)).Find(&oldQueries)
	for _, q := range oldQueries {
		if q.Completed {
			// Get query results
			var queriesData []OsqueryQueryData
			if err := logDB.Database.Conn.Where("name = ?", q.Name).Find(&queriesData).Error; err != nil {
				return err
			}
			if err := logDB.Database.Conn.Unscoped().Delete(&queriesData).Error; err != nil {
				return err
			}
			// Get query targets
			var queriesTargets []queries.DistributedQueryTarget
			if err := logDB.Database.Conn.Where("name = ?", q.Name).Find(&queriesTargets).Error; err != nil {
				return err
			}
			if err := logDB.Database.Conn.Unscoped().Delete(&queriesTargets).Error; err != nil {
				return err
			}
			// Delete query
			if err := logDB.Database.Conn.Unscoped().Delete(&q).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
