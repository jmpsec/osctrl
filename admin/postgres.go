package main

import (
	"encoding/json"
	"time"

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

// Function to retrieve the last status logs for a given node
func postgresStatusLogs(uuid, environment string, seconds int64) ([]OsqueryStatusData, error) {
	var logs []OsqueryStatusData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := db.Where("uuid = ? AND environment = ?", uuid, environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// Function to retrieve the last result logs for a given node
func postgresResultLogs(uuid, environment string, seconds int64) ([]OsqueryResultData, error) {
	var logs []OsqueryResultData
	minusSeconds := time.Now().Add(time.Duration(-seconds) * time.Second)
	if err := db.Where("uuid = ? AND environment = ?", uuid, environment).Where("created_at > ?", minusSeconds).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}

// Function to retrieve the query log by name
func postgresQueryLogs(name string) ([]OsqueryQueryData, error) {
	var logs []OsqueryQueryData
	if err := db.Where("name = ?", name).Find(&logs).Error; err != nil {
		return logs, err
	}
	return logs, nil
}
