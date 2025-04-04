package logging

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

// GraylogConfiguration to hold all graylog configuration values
type GraylogConfiguration struct {
	URL     string `json:"url"`
	Host    string `json:"host"`
	Queries string `json:"queries"`
	Status  string `json:"status"`
	Results string `json:"results"`
}

// LoadGraylog - Function to load the Graylog configuration from JSON file
func LoadGraylog(file string) (GraylogConfiguration, error) {
	var _graylogCfg GraylogConfiguration
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return _graylogCfg, err
	}
	cfgRaw := viper.Sub(config.LoggingGraylog)
	if cfgRaw == nil {
		return _graylogCfg, fmt.Errorf("JSON key %s not found in %s", config.LoggingGraylog, file)
	}
	if err := cfgRaw.Unmarshal(&_graylogCfg); err != nil {
		return _graylogCfg, err
	}
	// No errors!
	return _graylogCfg, nil
}

// LoggerGraylog will be used to log data using Graylog
type LoggerGraylog struct {
	Configuration GraylogConfiguration
	Headers       map[string]string
	Enabled       bool
}

// CreateLoggerGraylog to initialize the logger
func CreateLoggerGraylog(graylogFile string) (*LoggerGraylog, error) {
	config, err := LoadGraylog(graylogFile)
	if err != nil {
		return nil, err
	}
	l := &LoggerGraylog{
		Enabled: true,
		Headers: map[string]string{
			utils.ContentType: utils.JSONApplicationUTF8,
		},
		Configuration: config,
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
		jsonParam := strings.NewReader(string(jsonMessage))
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
