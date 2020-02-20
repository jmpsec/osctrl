package logging

import (
	"encoding/json"
	"log"

	"github.com/jinzhu/gorm"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

const (
	// DBName as JSON key for configuration
	DBName string = "db"
	// DBFile as default file for configuration
	DBFile string = "config/" + DBName + ".json"
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

func CreateLoggerDB() (*LoggerDB, error) {
	// Load DB configuration
	config, err := backend.LoadConfiguration(DBFile, DBName)
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
	return l, nil
}

// Settings - Function to prepare settings for the logger
func (logDB *LoggerDB) Settings(mgr *settings.Settings) {
	log.Printf("Setting DB logging settings\n")
	// Setting link for on-demand queries
	var _v string
	_v = settings.QueryLink
	if err := mgr.SetString(_v, settings.ServiceAdmin, settings.QueryResultLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", _v, settings.QueryResultLink, err)
	}
	_v = settings.StatusLink
	// Setting link for status logs
	if err := mgr.SetString(_v, settings.ServiceAdmin, settings.StatusLogsLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", _v, settings.StatusLogsLink, err)
	}
	_v = settings.ResultsLink
	// Setting link for result logs
	if err := mgr.SetString(_v, settings.ServiceAdmin, settings.ResultLogsLink, false); err != nil {
		log.Printf("Error setting %s with %s - %v", _v, settings.ResultLogsLink, err)
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
	err := json.Unmarshal(data, &logs)
	if err != nil {
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
	err := json.Unmarshal(data, &logs)
	if err != nil {
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
