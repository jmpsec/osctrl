package logging

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
)

// LoggerSplunk will be used to log data using Splunk
type LoggerSplunk struct {
	Configuration config.SplunkLogger
	Headers       map[string]string
	Enabled       bool
}

// CreateLoggerSplunk to initialize the logger
func CreateLoggerSplunk(cfg *config.SplunkLogger) (*LoggerSplunk, error) {
	l := &LoggerSplunk{
		Configuration: *cfg,
		Headers: map[string]string{
			utils.Authorization: "Splunk " + cfg.Token,
			utils.ContentType:   utils.JSONApplicationUTF8,
		},
		Enabled: true,
	}
	return l, nil
}

const (
	// SplunkMethod Method to send requests
	SplunkMethod = "POST"
	// SplunkContentType Content Type for requests
	SplunkContentType = "application/json"
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

// Settings - Function to prepare settings for the logger
func (logSP *LoggerSplunk) Settings(mgr *settings.Settings) {
	log.Info().Msg("Setting Splunk logging settings")
}

// Send - Function that sends JSON logs to Splunk HTTP Event Collector
func (logSP *LoggerSplunk) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("Send %s via splunk", logType)
	}
	// Check if this is result/status or query
	var sourceType string
	var logs []interface{}
	if logType == types.QueryLog {
		sourceType = logType
		// For on-demand queries, just a JSON blob with results and statuses
		var result interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			log.Err(err).Msgf("error parsing data %s", string(data))
		}
		logs = append(logs, result)
	} else {
		sourceType = logType + ":" + environment
		// For scheduled queries, convert the array in an array of multiple events
		if err := json.Unmarshal(data, &logs); err != nil {
			log.Err(err).Msgf("error parsing log %s", string(data))
		}
	}
	// Prepare data according to HTTP Event Collector format
	var events []SplunkMessage
	for _, l := range logs {
		jsonEvent, err := json.Marshal(l)
		if err != nil {
			log.Err(err).Msg("Error parsing data")
			continue
		}
		eventData := SplunkMessage{
			Time:       time.Now().Unix(),
			Host:       logSP.Configuration.Host,
			Source:     uuid,
			SourceType: sourceType,
			Index:      logSP.Configuration.Index,
			Event:      string(jsonEvent),
		}
		events = append(events, eventData)
	}
	// Serialize data for Splunk
	jsonEvents, err := json.Marshal(events)
	if err != nil {
		log.Err(err).Msgf("Error parsing data")
	}
	jsonParam := bytes.NewReader(jsonEvents)
	if debug {
		log.Debug().Msgf("Sending %d bytes to Splunk for %s - %s", len(data), environment, uuid)
	}
	// Send log with a POST to the Splunk URL
	resp, body, err := utils.SendRequest(SplunkMethod, logSP.Configuration.URL, jsonParam, logSP.Headers)
	if err != nil {
		log.Err(err).Msgf("Error sending request")
	}
	if debug {
		log.Debug().Msgf("HTTP %d %s", resp, body)
	}
}
