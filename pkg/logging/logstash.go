package logging

import (
	"fmt"
	"net"
	"strings"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/utils"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	// LogstashTCP for TCP inputs
	LogstashTCP = "tcp"
	// LogstashUDP for UDP inputs
	LogstashUDP = "udp"
	// LogstashHTTP for HTTP inputs
	LogstashHTTP = "http"
)

// LogstashConfiguration to hold all logstash configuration values
type LogstashConfiguration struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}

// LoggerLogstash will be used to log data using Logstash
type LoggerLogstash struct {
	Configuration LogstashConfiguration
	Headers       map[string]string
	Enabled       bool
}

// CreateLoggerLogstash to initialize the logger
func CreateLoggerLogstash(logstashFile string) (*LoggerLogstash, error) {
	config, err := LoadLogstash(logstashFile)
	if err != nil {
		return nil, err
	}
	l := &LoggerLogstash{
		Configuration: config,
		Headers: map[string]string{
			utils.ContentType: utils.JSONApplicationUTF8,
		},
		Enabled: true,
	}
	return l, nil
}

// LoadLogstash - Function to load the Logstash configuration from JSON file
func LoadLogstash(file string) (LogstashConfiguration, error) {
	var _logstashCfg LogstashConfiguration
	log.Info().Msgf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return _logstashCfg, err
	}
	cfgRaw := viper.Sub(settings.LoggingLogstash)
	if cfgRaw == nil {
		return _logstashCfg, fmt.Errorf("JSON key %s not found in %s", settings.LoggingLogstash, file)
	}
	if err := cfgRaw.Unmarshal(&_logstashCfg); err != nil {
		return _logstashCfg, err
	}
	// No errors!
	return _logstashCfg, nil
}

const (
	// LogstashMethod Method to send requests
	LogstashMethod = "POST"
	// LogstashContentType Content Type for requests
	LogstashContentType = "application/json"
	// LogstashConnStr Connection string for Logstash
	LogstashConnStr = "%s:%s"
)

// LogstashMessage to handle log format to be sent to Logstash
type LogstashMessage struct {
	Time        int64       `json:"time"`
	LogType     string      `json:"log_type"`
	UUID        string      `json:"uuid"`
	Environment string      `json:"environment"`
	Data        interface{} `json:"data"`
}

// Settings - Function to prepare settings for the logger
func (logLS *LoggerLogstash) Settings(mgr *settings.Settings) {
	log.Info().Msg("Setting Logstash logging settings")
}

// SendHTTP - Function that sends JSON logs to Logstash via HTTP
func (logLS *LoggerLogstash) SendHTTP(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("DebugService: Send %s via Logstash HTTP", logType)
	}
	jsonData := strings.NewReader(string(data))
	if debug {
		log.Debug().Msgf("DebugService: Sending %d bytes to Logstash HTTP for %s - %s", len(data), environment, uuid)
	}
	httpURL := fmt.Sprintf("http://%s:%s", logLS.Configuration.Host, logLS.Configuration.Port)
	// Send log with a POST to the Splunk URL
	resp, body, err := utils.SendRequest(LogstashMethod, httpURL, jsonData, logLS.Headers)
	if err != nil {
		log.Err(err).Msg("Error sending request")
	}
	if debug {
		log.Debug().Msgf("DebugService: HTTP %d %s", resp, body)
	}
}

// SendUDP - Function that sends data to Logstash via UDP
func (logLS *LoggerLogstash) SendUDP(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("DebugService: Send %s via Logstash TCP", logType)
	}
	if debug {
		log.Debug().Msgf("DebugService: Sending %d bytes to Logstash TCP for %s - %s", len(data), environment, uuid)
	}
	connAddr := fmt.Sprintf(LogstashConnStr, logLS.Configuration.Host, logLS.Configuration.Port)
	conn, err := net.Dial("udp", connAddr)
	if err != nil {
		log.Err(err).Msg("Error connecting to Logstash")
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		log.Err(err).Msg("Error writing to Logstash")
	}
	if debug {
		log.Debug().Msg("DebugService: Sent data to Logstash TCP")
	}
}

// SendTCP - Function that sends data to Logstash via TCP
func (logLS *LoggerLogstash) SendTCP(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("DebugService: Send %s via Logstash UDP", logType)
	}
	if debug {
		log.Debug().Msgf("DebugService: Sending %d bytes to Logstash UDP for %s - %s", len(data), environment, uuid)
	}
	connAddr := fmt.Sprintf(LogstashConnStr, logLS.Configuration.Host, logLS.Configuration.Port)
	conn, err := net.Dial("tcp", connAddr)
	if err != nil {
		log.Err(err).Msg("Error connecting to Logstash")
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		log.Err(err).Msg("Error writing to Logstash")
	}
	if debug {
		log.Debug().Msg("DebugService: Sent data to Logstash UDP")
	}
}
