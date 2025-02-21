package logging

import (
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/rs/zerolog/log"
)

// LoggerStdout will be used to log data using stdout
type LoggerStdout struct {
	Enabled bool
}

// CreateLoggerStdout to initialize the logger
func CreateLoggerStdout() (*LoggerStdout, error) {
	return &LoggerStdout{
		Enabled: true,
	}, nil
}

// Settings - Function to prepare settings for the logger
func (logStdout *LoggerStdout) Settings(mgr *settings.Settings) {
	log.Info().Msg("No stdout logging settings")
}

// Log - Function that sends JSON result/status/query logs to stdout
func (logStdout *LoggerStdout) Log(logType string, data []byte, environment, uuid string, debug bool) {
	switch logType {
	case types.StatusLog:
		logStdout.Status(data, environment, uuid, debug)
	case types.ResultLog:
		logStdout.Result(data, environment, uuid, debug)
	}
}

// Status - Function that sends JSON status logs to stdout
func (logStdout *LoggerStdout) Status(data []byte, environment, uuid string, debug bool) {
	log.Info().Msgf("Status: %s:%s - %d bytes [%s]", environment, uuid, len(data), string(data))
}

// Result - Function that sends JSON result logs to stdout
func (logStdout *LoggerStdout) Result(data []byte, environment, uuid string, debug bool) {
	log.Info().Msgf("Result: %s:%s - %d bytes [%s]", environment, uuid, len(data), string(data))
}

// Query - Function that sends JSON query logs to stdout
func (logStdout *LoggerStdout) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	log.Info().Msgf("Query: %s:%d - %s:%s - %d bytes [%s]", name, status, environment, uuid, len(data), string(data))
}
