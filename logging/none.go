package logging

import (
	"log"

	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
)

// LoggerNone will be used to not log any data
type LoggerNone struct {
	Enabled bool
}

// CreateLoggerNone to initialize the logger
func CreateLoggerNone() (*LoggerNone, error) {
	return &LoggerNone{Enabled: true}, nil
}

// Settings - Function to prepare settings for the logger
func (logNone *LoggerNone) Settings(mgr *settings.Settings) {
	log.Printf("No none logging settings\n")
}

// Log - Function that sends JSON result/status/query logs to stdout
func (logNone *LoggerNone) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Printf("Sending %d bytes to none for %s - %s", len(data), environment, uuid)
	}
	switch logType {
	case types.StatusLog:
		logNone.Status(data, environment, uuid, debug)
	case types.ResultLog:
		logNone.Result(data, environment, uuid, debug)
	}
}

// Status - Function that sends JSON status logs to stdout
func (logNone *LoggerNone) Status(data []byte, environment, uuid string, debug bool) {
	log.Printf("Skipping to log %d bytes of status from %s/%s", len(data), environment, uuid)
}

// Result - Function that sends JSON result logs to stdout
func (logNone *LoggerNone) Result(data []byte, environment, uuid string, debug bool) {
	log.Printf("Skipping to log %d bytes of result from %s/%s", len(data), environment, uuid)
}

// Query - Function that sends JSON query logs to stdout
func (logNone *LoggerNone) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	log.Printf("Skipping to log %d bytes of query from %s/%s for query %s and status %d", len(data), environment, uuid, name, status)
}
