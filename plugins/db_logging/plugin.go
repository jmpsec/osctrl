package main

import (
	"encoding/json"
	"log"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jinzhu/gorm"
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

// DBLog - Function that sends JSON result/status/query logs to the configured DB
// FIXME maybe allow different DB to be used than the one from the service
func DBLog(logType string, db *gorm.DB, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("Sending %d bytes to DB for %s - %s", len(data), environment, uuid)
	}
	switch logType {
	case types.StatusLog:
		dbStatus(db, data, environment, uuid, debug)
	case types.ResultLog:
		dbResult(db, data, environment, uuid, debug)
	}
}

// dbStatus - Function that sends JSON status logs to the configured DB
func dbStatus(db *gorm.DB, data []byte, environment, uuid string, debug bool) {
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
		if db.NewRecord(entry) {
			if err := db.Create(&entry).Error; err != nil {
				log.Printf("Error creating status log entry %s", err)
			}
		} else {
			log.Printf("db.NewRecord did not return true")
		}
	}
}

// dbResult - Function that sends JSON result logs to the configured DB
func dbResult(db *gorm.DB, data []byte, environment, uuid string, debug bool) {
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
		if db.NewRecord(entry) {
			if err := db.Create(&entry).Error; err != nil {
				log.Printf("Error creating result log entry %s", err)
			}
		} else {
			log.Printf("db.NewRecord did not return true")
		}
	}
}

// DBQuery - Function that sends JSON query logs to the configured DB
func DBQuery(db *gorm.DB, data []byte, environment, uuid, name string, status int, debug bool) {
	// Prepare data
	entry := OsqueryQueryData{
		UUID:        uuid,
		Environment: environment,
		Name:        name,
		Data:        data,
		Status:      status,
	}
	// Insert in DB
	if db.NewRecord(entry) {
		if err := db.Create(&entry).Error; err != nil {
			log.Printf("Error creating query log %s", err)
		}
	} else {
		log.Printf("db.NewRecord did not return true")
	}
}
