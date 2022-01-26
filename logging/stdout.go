package logging

import (
	"log"
	"os"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
	"github.com/rs/zerolog"
)

// LoggerStdout will be used to log data using stdout
type LoggerStdout struct {
	Enabled bool
	Logger  *zerolog.Logger
}

// CreateLoggerStdout to initialize the logger
func CreateLoggerStdout() (*LoggerStdout, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	return &LoggerStdout{
		Enabled: true,
		Logger:  &logger,
	}, nil
}

// Settings - Function to prepare settings for the logger
func (logStdout *LoggerStdout) Settings(mgr *settings.Settings) {
	log.Printf("No stdout logging settings\n")
}

// Log - Function that sends JSON result/status/query logs to stdout
func (logStdout *LoggerStdout) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("Sending %d bytes to stdout for %s - %s", len(data), environment, uuid)
	}
	switch logType {
	case types.StatusLog:
		logStdout.Status(data, environment, uuid, debug)
	case types.ResultLog:
		logStdout.Result(data, environment, uuid, debug)
	}
}

// Status - Function that sends JSON status logs to stdout
func (logStdout *LoggerStdout) Status(data []byte, environment, uuid string, debug bool) {
	logStdout.Logger.Info().Str(
		"type", types.StatusLog).Str(
		"environment", environment).Str(
		"uuid", uuid).RawJSON("data", data)
}

// Result - Function that sends JSON result logs to stdout
func (logStdout *LoggerStdout) Result(data []byte, environment, uuid string, debug bool) {
	logStdout.Logger.Info().Str(
		"type", types.ResultLog).Str(
		"environment", environment).Str(
		"uuid", uuid).RawJSON("data", data)
}

// Query - Function that sends JSON query logs to stdout
func (logStdout *LoggerStdout) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	logStdout.Logger.Info().Str(
		"type", types.QueryLog).Str(
		"environment", environment).Str(
		"name", name).Int(
		"status", status).Str(
		"uuid", uuid).RawJSON("data", data)
}
