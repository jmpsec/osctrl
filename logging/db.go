package logging

import (
	"encoding/json"
	"log"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

// OsqueryResultData to log result data to database
type OsqueryResultData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Name        string
	Action      string
	Epoch       int64
	Columns     json.RawMessage
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
	Data        json.RawMessage
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
	} else if err := mgr.SetString(settings.QueryLink, settings.ServiceAdmin, settings.QueryResultLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", settings.QueryResultLink, settings.QueryLink, err)
	}
	// Setting link for status logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.StatusLogsLink) {
		if err := mgr.NewStringValue(settings.ServiceAdmin, settings.StatusLogsLink, settings.StatusLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	} else if err := mgr.SetString(settings.StatusLink, settings.ServiceAdmin, settings.StatusLogsLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", settings.StatusLogsLink, settings.StatusLink, err)
	}
	// Setting link for result logs
	if !mgr.IsValue(settings.ServiceAdmin, settings.ResultLogsLink) {
		if err := mgr.NewStringValue(settings.ServiceAdmin, settings.ResultLogsLink, settings.ResultsLink); err != nil {
			log.Fatalf("Failed to add %s to settings: %v", settings.DebugHTTP, err)
		}
	} else if err := mgr.SetString(settings.ResultsLink, settings.ServiceAdmin, settings.ResultLogsLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", settings.ResultLogsLink, settings.ResultsLink, err)
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
			UUID:        l.HostIdentifier,
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
			UUID:        l.HostIdentifier,
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
		UUID:        uuid,
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
	if err := logDB.Database.Where("uuid = ? AND environment = ?", uuid, environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// ResultLogs will retrieve all result logs
func (logDB *LoggerDB) ResultLogs(uuid, environment string, seconds int64) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := logDB.Database.Where("uuid = ? AND environment = ?", uuid, environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}
