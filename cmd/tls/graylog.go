package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

const (
	// GraylogVersion GELF spec version
	GraylogVersion = "1.1"
	// GraylogHost as source for GELF data
	GraylogHost = projectName
	// GraylogLevel informational
	GraylogLevel = 6
	// GraylogMethod to send
	GraylogMethod = "POST"
)

// GraylogMessage to handle log format to be sent to Graylog
type GraylogMessage struct {
	Version      string `json:"version"`
	Host         string `json:"host"`
	ShortMessage string `json:"short_message"`
	Timestamp    int64  `json:"timestamp"`
	Level        uint   `json:"level"`
	Context      string `json:"_context"`
	Type         string `json:"_type"`
	UUID         string `json:"_uuid"`
}

// Function that sends JSON logs to Graylog
func graylogSend(data []byte, context, logType, uuid string, configData LoggingConfigurationData) {
	// Prepare headers
	headers := map[string]string{
		"Content-Type": JSONApplication,
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
			Version:      GraylogVersion,
			Host:         GraylogHost,
			ShortMessage: string(jsonMessage),
			Timestamp:    time.Now().Unix(),
			Level:        GraylogLevel,
			Context:      context,
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
	// Send log with a POST to the Graylog URL
	resp, body, err := sendRequest(true, GraylogMethod, configData["url"], jsonParam, headers)
	if err != nil {
		log.Printf("Error sending request %s", err)
		return
	}
	if contexts[context].DebugHTTP {
		log.Printf("Graylog: HTTP %d %s", resp, body)
	}
}
