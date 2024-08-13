package main

import (
	"github.com/jmpsec/osctrl/logging"
)

type APIQueryData map[string]string

// Function to retrieve the query log by name
func postgresQueryLogs(name string) (APIQueryData, error) {
	var logs []logging.OsqueryQueryData
	data := make(APIQueryData)
	if err := db.Conn.Where("name = ?", name).Find(&logs).Error; err != nil {
		return data, err
	}
	for _, l := range logs {
		data[l.UUID] = l.Data
	}
	return data, nil
}
