package main

import (
	"gorm.io/gorm"
)

// OsqueryQueryData to log query data to database
type OsqueryQueryData struct {
	gorm.Model
	UUID        string `gorm:"index"`
	Environment string
	Name        string
	Data        string
	Status      int
}

// APIQueryData to return query results from API
type APIQueryData map[string]string

// Function to retrieve the query log by name
func postgresQueryLogs(name string) (APIQueryData, error) {
	var logs []OsqueryQueryData
	data := make(APIQueryData)
	if err := db.Conn.Where("name = ?", name).Find(&logs).Error; err != nil {
		return data, err
	}
	for _, l := range logs {
		data[l.UUID] = l.Data
	}
	return data, nil
}
