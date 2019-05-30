package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

const (
	// SplunkHost as source for Splunk events
	SplunkHost = projectName
	// SplunkMethod to send
	SplunkMethod = "POST"
	// SplunkIndex to go to the right index
	SplunkIndex = "osquery"
)

// SplunkMessage to handle log format to be sent to Splunk
type SplunkMessage struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host"`
	Source     string      `json:"source"`
	SourceType string      `json:"sourcetype"`
	Index      string      `json:"index"`
	Event      interface{} `json:"event"`
}

// Function that sends JSON logs to Splunk HTTP Event Collector
func splunkSend(data []byte, context, logType, uuid string, configData LoggingConfigurationData) {
	// Prepare headers
	headers := map[string]string{
		"Authorization": "Splunk " + configData["token"],
		"Content-Type":  JSONApplication,
	}
	// Check if this is result/status or query
	var sourceType string
	var logs []interface{}
	if logType == "query" {
		sourceType = logType
		// For on-demand queries, just a JSON blob with results and statuses
		var result interface{}
		err := json.Unmarshal(data, &result)
		if err != nil {
			log.Printf("error parsing data %s %v", string(data), err)
		}
		logs = append(logs, result)
	} else {
		sourceType = logType + ":" + context
		// For scheduled queries, convert the array in an array of multiple events
		err := json.Unmarshal(data, &logs)
		if err != nil {
			log.Printf("error parsing log %s %v", string(data), err)
		}
	}
	// Prepare data according to HTTP Event Collector format
	var events []SplunkMessage
	for _, l := range logs {
		jsonEvent, err := json.Marshal(l)
		if err != nil {
			log.Printf("Error parsing data %s", err)
			continue
		}
		eventData := SplunkMessage{
			Time:       time.Now().Unix(),
			Host:       SplunkHost,
			Source:     uuid,
			SourceType: sourceType,
			Index:      SplunkIndex,
			Event:      string(jsonEvent),
		}
		events = append(events, eventData)
	}
	// Serialize data for Splunk
	jsonEvents, err := json.Marshal(events)
	if err != nil {
		log.Printf("Error parsing data %s", err)
	}
	jsonParam := strings.NewReader(string(jsonEvents))
	// Send log with a POST to the Splunk URL
	resp, body, err := sendRequest(true, SplunkMethod, configData["url"], jsonParam, headers)
	if err != nil {
		log.Printf("Error sending request %s", err)
	}
	if config.DebugHTTP(serviceTLS) {
		log.Printf("Splunk: HTTP %d %s", resp, body)
	}
}
