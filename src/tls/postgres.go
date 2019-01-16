package main

import (
	"encoding/json"
	"log"
	"time"

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
	Status  int
}

// Function that sends JSON query logs to the configured PostgreSQL DB
func postgresQuery(data []byte, name string, node OsqueryNode, status int) {
	// Prepare data
	entry := OsqueryQueryData{
		UUID:    node.UUID,
		Context: node.Context,
		Name:    name,
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

// Function to retrieve the last status logs for a given node
func postgresStatusLogs(uuid, context string, seconds int64) ([]OsqueryStatusData, error) {
	var logs []OsqueryStatusData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := db.Where("uuid = ? AND context = ?", uuid, context).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// Function to retrieve the last result logs for a given node
func postgresResultLogs(uuid, context string, seconds int64) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := db.Where("uuid = ? AND context = ?", uuid, context).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// Function to retrieve the query log by name
func postgresQueryLogs(name string) ([]OsqueryQueryData, error) {
	var logs []OsqueryQueryData
	if err := db.Where("name = ?", "query", name).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}
