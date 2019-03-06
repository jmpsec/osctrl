package main

import (
	"encoding/json"
	"log"

	"github.com/javuto/osctrl/nodes"
	"github.com/jinzhu/gorm"
)

// OsqueryResultData to log result data to database
type OsqueryResultData struct {
	gorm.Model
	UUID    string `gorm:"index"`
	Context string
	Name    string
	Action  string
	Epoch   int64
	Columns json.RawMessage
	Counter int
}

// OsqueryStatusData to log status data to database
type OsqueryStatusData struct {
	gorm.Model
	UUID     string `gorm:"index"`
	Context  string
	Line     string
	Message  string
	Version  string
	Filename string
	Severity string
}

// Function that sends JSON result/status logs to the configured PostgreSQL DB
func postgresLog(data []byte, context, logType, uuid string) {
	if logType == statusLog {
		// Parse JSON
		var logs []LogStatusData
		err := json.Unmarshal(data, &logs)
		if err != nil {
			log.Printf("error parsing logs %s %v", string(data), err)
		}
		// Iterate and insert in DB
		for _, l := range logs {
			entry := OsqueryStatusData{
				UUID:     l.HostIdentifier,
				Context:  context,
				Line:     l.Line,
				Message:  l.Message,
				Version:  l.Version,
				Filename: l.Filename,
				Severity: l.Severity,
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
	if logType == resultLog {
		// Parse JSON
		var logs []LogResultData
		err := json.Unmarshal(data, &logs)
		if err != nil {
			log.Printf("error parsing logs %s %v", string(data), err)
		}
		// Iterate and insert in DB
		for _, l := range logs {
			entry := OsqueryResultData{
				UUID:    l.HostIdentifier,
				Context: context,
				Name:    l.Name,
				Action:  l.Action,
				Epoch:   l.Epoch,
				Columns: l.Columns,
				Counter: l.Counter,
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
}

// OsqueryQueryData to log query data to database
type OsqueryQueryData struct {
	gorm.Model
	UUID    string `gorm:"index"`
	Context string
	Name    string
	Data    json.RawMessage
	Status  int
}

// Function that sends JSON query logs to the configured PostgreSQL DB
func postgresQuery(data []byte, name string, node nodes.OsqueryNode, status int) {
	// Prepare data
	entry := OsqueryQueryData{
		UUID:    node.UUID,
		Context: node.Context,
		Name:    name,
		Data:    data,
		Status:  status,
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
