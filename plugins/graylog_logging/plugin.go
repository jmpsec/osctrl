package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/javuto/osctrl/pkg/utils"
)

const (
	// GELF spec version
	graylogVersion = "1.1"
	// Host as source for GELF data
	graylogHost = "osctrl"
	// Log Level (informational)
	graylogLevel = 6
	// Method to send
	graylogMethod = "POST"
)

// GraylogMessage to handle log format to be sent to Graylog
type GraylogMessage struct {
	Version      string `json:"version"`
	Host         string `json:"host"`
	ShortMessage string `json:"short_message"`
	Timestamp    int64  `json:"timestamp"`
	Level        uint   `json:"level"`
	Environment  string `json:"_environment"`
	Type         string `json:"_type"`
	UUID         string `json:"_uuid"`
}

// GraylogSend - Function that sends JSON logs to Graylog
func GraylogSend(logType string, data []byte, environment, uuid, url string, debug bool) {
	// Prepare headers
	headers := map[string]string{
		"Content-Type": "application/json",
	}
	// Convert the array in an array of multiple message
	var logs []interface{}
	err := json.Unmarshal(data, &logs)
	if err != nil {
		log.Printf("error parsing log %s %v", string(data), err)
	}
	// Prepare data to send
	var messages []GraylogMessage
	for _, l := range logs {
		jsonMessage, err := json.Marshal(l)
		if err != nil {
			log.Printf("Error parsing data %s", err)
			continue
		}
		messsageData := GraylogMessage{
			Version:      graylogVersion,
			Host:         graylogHost,
			ShortMessage: string(jsonMessage),
			Timestamp:    time.Now().Unix(),
			Level:        graylogLevel,
			Environment:  environment,
			Type:         logType,
			UUID:         uuid,
		}
		messages = append(messages, messsageData)
	}
	// Serialize data using GELF
	jsonMessages, err := json.Marshal(messages)
	if err != nil {
		log.Printf("Error parsing data %s", err)
	}
	jsonParam := strings.NewReader(string(jsonMessages))
	if debug {
		log.Printf("Sending %d bytes to Graylog for %s - %s", len(data), environment, uuid)
	}
	// Send log with a POST to the Graylog URL
	resp, body, err := utils.SendRequest(true, graylogMethod, url, jsonParam, headers)
	if err != nil {
		log.Printf("Error sending request %s", err)
		return
	}
	if debug {
		log.Printf("Graylog: HTTP %d %s", resp, body)
	}
}
