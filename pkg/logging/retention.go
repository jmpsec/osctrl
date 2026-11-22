package logging

import (
	"errors"
	"fmt"
	"time"
)

// PruneStats reports how many database-backed log rows were deleted for one
// environment. Table-specific counts make an unexpected zero easy to spot in
// the worker log without turning on debug logging.
type PruneStats struct {
	StatusLogs int64
	ResultLogs int64
	QueryLogs  int64
}

// PruneEnvironment hard-deletes status, result and on-demand query rows for
// one environment that were created before the cutoff. Each table is pruned
// independently: a missing table (for example a deployment that never enabled
// DB logging) does not prevent the others from being cleaned, and the joined
// error reports every table that failed.
func (logDB *LoggerDB) PruneEnvironment(environment string, before time.Time) (PruneStats, error) {
	var stats PruneStats
	if logDB == nil || logDB.Database == nil || logDB.Database.Conn == nil {
		return stats, fmt.Errorf("log retention: database logger is not initialized")
	}

	var errs []error
	if deleted, err := logDB.CleanStatusLogsBefore(environment, before); err != nil {
		errs = append(errs, err)
	} else {
		stats.StatusLogs = deleted
	}
	if deleted, err := logDB.CleanResultLogsBefore(environment, before); err != nil {
		errs = append(errs, err)
	} else {
		stats.ResultLogs = deleted
	}
	if deleted, err := logDB.CleanQueryLogsBefore(environment, before); err != nil {
		errs = append(errs, err)
	} else {
		stats.QueryLogs = deleted
	}
	return stats, errors.Join(errs...)
}

// CleanStatusLogsBefore deletes status-log rows for environment older than
// before and returns the number of rows removed.
func (logDB *LoggerDB) CleanStatusLogsBefore(environment string, before time.Time) (int64, error) {
	if logDB == nil || logDB.Database == nil || logDB.Database.Conn == nil {
		return 0, fmt.Errorf("CleanStatusLogsBefore: database logger is not initialized")
	}
	result := logDB.Database.Conn.Unscoped().
		Where("environment = ?", environment).
		Where("created_at < ?", before).
		Delete(&OsqueryStatusData{})
	if result.Error != nil {
		return result.RowsAffected, fmt.Errorf("CleanStatusLogsBefore %w", result.Error)
	}
	return result.RowsAffected, nil
}

// CleanResultLogsBefore deletes result-log rows for environment older than
// before and returns the number of rows removed.
func (logDB *LoggerDB) CleanResultLogsBefore(environment string, before time.Time) (int64, error) {
	if logDB == nil || logDB.Database == nil || logDB.Database.Conn == nil {
		return 0, fmt.Errorf("CleanResultLogsBefore: database logger is not initialized")
	}
	result := logDB.Database.Conn.Unscoped().
		Where("environment = ?", environment).
		Where("created_at < ?", before).
		Delete(&OsqueryResultData{})
	if result.Error != nil {
		return result.RowsAffected, fmt.Errorf("CleanResultLogsBefore %w", result.Error)
	}
	return result.RowsAffected, nil
}

// CleanQueryLogsBefore deletes on-demand query-result rows for environment
// older than before and returns the number of rows removed.
func (logDB *LoggerDB) CleanQueryLogsBefore(environment string, before time.Time) (int64, error) {
	if logDB == nil || logDB.Database == nil || logDB.Database.Conn == nil {
		return 0, fmt.Errorf("CleanQueryLogsBefore: database logger is not initialized")
	}
	result := logDB.Database.Conn.Unscoped().
		Where("environment = ?", environment).
		Where("created_at < ?", before).
		Delete(&OsqueryQueryData{})
	if result.Error != nil {
		return result.RowsAffected, fmt.Errorf("CleanQueryLogsBefore %w", result.Error)
	}
	return result.RowsAffected, nil
}
