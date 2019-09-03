package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
)

const (
	// Source for Splunk events
	splunkHost = "osctrl"
	// Method to send requests
	splunkMethod string = "POST"
	// Index to use
	splunkIndex string = "osquery"
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

// SplunkSend - Function that sends JSON logs to Splunk HTTP Event Collector
func SplunkSend(logType string, data []byte, environment, uuid, url, token string, debug bool) {
	// Prepare headers
	headers := map[string]string{
		"Authorization": "Splunk " + token,
		"Content-Type":  "application/json",
	}
	// Check if this is result/status or query
	var sourceType string
	var logs []interface{}
	if logType == types.QueryLog {
		sourceType = logType
		// For on-demand queries, just a JSON blob with results and statuses
		var result interface{}
		err := json.Unmarshal(data, &result)
		if err != nil {
			log.Printf("error parsing data %s %v", string(data), err)
		}
		logs = append(logs, result)
	} else {
		sourceType = logType + ":" + environment
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
			Host:       splunkHost,
			Source:     uuid,
			SourceType: sourceType,
			Index:      splunkIndex,
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
	if debug {
		log.Printf("Sending %d bytes to Splunk for %s - %s", len(data), environment, uuid)
	}
	// Send log with a POST to the Splunk URL
	resp, body, err := utils.SendRequest(splunkMethod, url, jsonParam, headers)
	if err != nil {
		log.Printf("Error sending request %s", err)
	}
	if debug {
		log.Printf("Splunk: HTTP %d %s", resp, body)
	}
}
