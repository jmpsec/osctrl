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

// LoggerGraylog will be used to log data using Graylog
type LoggerGraylog struct {
	Configuration config.GraylogLogger
	Headers       map[string]string
	Enabled       bool
}

// CreateLoggerGraylog to initialize the logger
func CreateLoggerGraylog(cfg *config.GraylogLogger) (*LoggerGraylog, error) {
	l := &LoggerGraylog{
		Enabled: true,
		Headers: map[string]string{
			utils.ContentType: utils.JSONApplicationUTF8,
		},
		Configuration: *cfg,
	}
	return l, nil
}

const (
	// GraylogVersion - GELF spec version
	GraylogVersion = "1.1"
	// GraylogLevel - Log Level (informational)
	GraylogLevel = 6
	// GraylogMethod - Method to send
	GraylogMethod = "POST"
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

// Settings - Function to prepare settings for the logger
func (logGL *LoggerGraylog) Settings(mgr *settings.Settings) {
	log.Info().Msg("No Graylog logging settings")
}

// Send - Function that sends JSON logs to Graylog
func (logGL *LoggerGraylog) Send(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("Send %s via graylog", logType)
	}
	// Convert the array in an array of multiple message
	var logs []interface{}
	if logType == types.QueryLog {
		// For on-demand queries, just a JSON blob with results and statuses
		var result interface{}
		err := json.Unmarshal(data, &result)
		if err != nil {
			log.Err(err).Msgf("error parsing data %s", string(data))
		}
		logs = append(logs, result)
	} else {
		err := json.Unmarshal(data, &logs)
		if err != nil {
			log.Err(err).Msgf("error parsing logs %s", string(data))
		}
	}
	// Prepare data to send
	for _, l := range logs {
		logMessage, err := json.Marshal(l)
		if err != nil {
			log.Err(err).Msg("error parsing log")
			continue
		}
		messsageData := GraylogMessage{
			Version:      GraylogVersion,
			Host:         logGL.Configuration.Host,
			ShortMessage: string(logMessage),
			Timestamp:    time.Now().Unix(),
			Level:        GraylogLevel,
			Environment:  environment,
			Type:         logType,
			UUID:         uuid,
		}
		// Serialize data using GELF
		jsonMessage, err := json.Marshal(messsageData)
		if err != nil {
			log.Err(err).Msg("error marshaling data")
		}
		jsonParam := bytes.NewReader(jsonMessage)
		if debug {
			log.Debug().Msgf("Sending %d bytes to Graylog for %s - %s", len(data), environment, uuid)
		}
		// Send log with a POST to the Graylog URL
		resp, body, err := utils.SendRequest(GraylogMethod, logGL.Configuration.URL, jsonParam, logGL.Headers)
		if err != nil {
			log.Err(err).Msg("error sending request")
			return
		}
		if debug {
			log.Debug().Msgf("HTTP %d %s", resp, body)
		}
	}
}
