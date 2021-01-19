package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

const (
	// Default interval in seconds for cleanup old logs
	defaultCleanupInterval = 86400
)

// OsqueryResultData to log result data to database
type OsqueryResultData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Name        string
	Action      string
	Epoch       int64
	Columns     []byte
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
	Data        []byte
	Status      int
}

// LoggerDB will be used to log data using a database
type LoggerDB struct {
	Database      *gorm.DB
	Configuration backend.JSONConfigurationDB
	Enabled       bool
}

func CreateLoggerDB(dbfile, dbname string) (*LoggerDB, error) {
	// Load DB configuration
	config, err := backend.LoadConfiguration(dbfile, dbname)
	if err != nil {
		return nil, err
	}
	// Connect to DB
	database, err := backend.GetDB(config)
	if err != nil {
		return nil, err
	}
	l := &LoggerDB{
		Database:      database,
		Configuration: config,
		Enabled:       true,
	}
	// table osquery_status_data
	if err := database.AutoMigrate(OsqueryStatusData{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_status_data): %v", err)
	}
	// table osquery_result_data
	if err := database.AutoMigrate(OsqueryResultData{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_result_data): %v", err)
	}
	// table osquery_query_data
	if err := database.AutoMigrate(OsqueryQueryData{}).Error; err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_query_data): %v", err)
	}
	return l, nil
}

// Settings - Function to prepare settings for the logger
func (logDB *LoggerDB) Settings(mgr *settings.Settings) {
	log.Printf("Setting DB logging settings\n")
	// Setting link for on-demand queries
	if !mgr.IsValue(settings.ServiceAdmin, settings.QueryResultLink) {
		if err := mgr.NewStringValue(settings.ServiceAdmin, settings.QueryResultLink, settings.QueryLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.QueryResultLink, err)
		}
	}
	// Setting link for status logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.StatusLogsLink) {
		if err := mgr.NewStringValue(settings.ServiceAdmin, settings.StatusLogsLink, settings.StatusLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.StatusLogsLink, err)
		}
	}
	// Setting link for result logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.ResultLogsLink) {
		if err := mgr.NewStringValue(settings.ServiceAdmin, settings.ResultLogsLink, settings.ResultsLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.ResultLogsLink, err)
		}
	}
	// Setting values to enable log cleanup for status logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanStatusLogs) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.CleanStatusLogs, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanStatusLogs, err)
		}
	}
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanStatusInterval) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanStatusInterval, defaultCleanupInterval); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanStatusInterval, err)
		}
	}
	// Setting values to enable log cleanup for result logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanResultLogs) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.CleanResultLogs, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanResultLogs, err)
		}
	}
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanResultInterval) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanResultInterval, defaultCleanupInterval); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanResultInterval, err)
		}
	}
	// Setting values to enable log cleanup for query logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanQueryLogs) {
		if err := mgr.NewBooleanValue(settings.ServiceAdmin, settings.CleanQueryLogs, false); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanQueryLogs, err)
		}
	}
	if !mgr.IsValue(settings.ServiceAdmin, settings.CleanQueryEntries) {
		if err := mgr.NewIntegerValue(settings.ServiceAdmin, settings.CleanQueryEntries, 100); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.CleanQueryEntries, err)
		}
	}
}

// Log - Function that sends JSON result/status/query logs to the configured DB
func (logDB *LoggerDB) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("Sending %d bytes to DB for %s - %s", len(data), environment, uuid)
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
		log.Printf("error parsing logs %s %v", string(data), err)
	}
	// Iterate and insert in DB
	for _, l := range logs {
		entry := OsqueryStatusData{
			UUID:        strings.ToUpper(l.HostIdentifier),
			Environment: environment,
			Line:        l.Line,
			Message:     l.Message,
			Version:     l.Version,
			Filename:    l.Filename,
			Severity:    l.Severity,
		}
		if logDB.Database.NewRecord(entry) {
			if err := logDB.Database.Create(&entry).Error; err != nil {
				log.Printf("Error creating status log entry %s", err)
			}
		} else {
			log.Printf("NewRecord did not return true")
		}
	}
}

// dbResult - Function that sends JSON result logs to the configured DB
func (logDB *LoggerDB) Result(data []byte, environment, uuid string, debug bool) {
	// Parse JSON
	var logs []types.LogResultData
	if err := json.Unmarshal(data, &logs); err != nil {
		log.Printf("error parsing logs %s %v", string(data), err)
	}
	// Iterate and insert in DB
	for _, l := range logs {
		entry := OsqueryResultData{
			UUID:        strings.ToUpper(l.HostIdentifier),
			Environment: environment,
			Name:        l.Name,
			Action:      l.Action,
			Epoch:       l.Epoch,
			Columns:     l.Columns,
			Counter:     l.Counter,
		}
		if logDB.Database.NewRecord(entry) {
			if err := logDB.Database.Create(&entry).Error; err != nil {
				log.Printf("Error creating result log entry %s", err)
			}
		} else {
			log.Printf("NewRecord did not return true")
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
		Data:        data,
		Status:      status,
	}
	// Insert in DB
	if logDB.Database.NewRecord(entry) {
		if err := logDB.Database.Create(&entry).Error; err != nil {
			log.Printf("Error creating query log %s", err)
		}
	} else {
		log.Printf("NewRecord did not return true")
	}
}

// QueryLogs will retrieve all query logs
func (logDB *LoggerDB) QueryLogs(name string) ([]OsqueryQueryData, error) {
	var logs []OsqueryQueryData
	if err := logDB.Database.Where("name = ?", name).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// StatusLogs will retrieve all status logs
func (logDB *LoggerDB) StatusLogs(uuid, environment string, seconds int64) ([]OsqueryStatusData, error) {
	var logs []OsqueryStatusData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// ResultLogs will retrieve all result logs
func (logDB *LoggerDB) ResultLogs(uuid, environment string, seconds int64) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Where("uuid = ? AND environment = ?", strings.ToUpper(uuid), environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// CleanStatusLogs will delete old status logs
func (logDB *LoggerDB) CleanStatusLogs(environment string, seconds int64) error {
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Unscoped().Where("environment = ?", environment).Where("created_at < ?", minusSeconds).Delete(&OsqueryStatusData{}).Error; err != nil {
		return fmt.Errorf("CleanStatusLogs %v", err)
	}
	return nil
}

// CleanResultLogs will delete old status logs
func (logDB *LoggerDB) CleanResultLogs(environment string, seconds int64) error {
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Unscoped().Where("environment = ?", environment).Where("created_at < ?", minusSeconds).Delete(&OsqueryResultData{}).Error; err != nil {
		return fmt.Errorf("CleanResultLogs %v", err)
	}
	return nil
}

// CleanQueryLogs will delete old query logs
func (logDB *LoggerDB) CleanQueryLogs(entries int64) error {
	// TODO this would be better and simpler with foreign keys and delete cascade
	// Find queries to delete with OFFSET
	var oldQueries []queries.DistributedQuery
	logDB.Database.Offset(entries).Find(&oldQueries)
	for _, q := range oldQueries {
		if q.Completed {
			// Get query results
			var queriesData []OsqueryQueryData
			if err := logDB.Database.Where("name = ?", q.Name).Find(&queriesData).Error; err != nil {
				return err
			}
			if err := logDB.Database.Unscoped().Delete(&queriesData).Error; err != nil {
				return err
			}
			// Get query targets
			var queriesTargets []queries.DistributedQueryTarget
			if err := logDB.Database.Where("name = ?", q.Name).Find(&queriesTargets).Error; err != nil {
				return err
			}
			if err := logDB.Database.Unscoped().Delete(&queriesTargets).Error; err != nil {
				return err
			}
			// Get query executions
			var queriesExecutions []queries.DistributedQueryExecution
			if err := logDB.Database.Where("name = ?", q.Name).Find(&queriesExecutions).Error; err != nil {
				return err
			}
			if err := logDB.Database.Unscoped().Delete(&queriesExecutions).Error; err != nil {
				return err
			}
			// Delete query
			if err := logDB.Database.Unscoped().Delete(&q).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
