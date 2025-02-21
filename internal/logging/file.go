package logging

import (
	"osctrl/internal/settings"
	"osctrl/internal/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// LumberjackConfig to keep configuration for rotating logs
type LumberjackConfig struct {
	// Maximum size in megabytes of the log file before it gets rotated
	MaxSize int
	// Maximum number of old log files to retain
	MaxBackups int
	// Maximum number of days to retain old log files based on the timestamp encoded in their filename
	MaxAge int
	// If the rotated log files should be compressed using gzip
	Compress bool
}

// LoggerFile will be used to log data using external file
type LoggerFile struct {
	Enabled  bool
	Filename string
	Logger   *zerolog.Logger
}

// CreateLoggerFile to initialize the logger
func CreateLoggerFile(filename string, cfg LumberjackConfig) (*LoggerFile, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	z := zerolog.New(&lumberjack.Logger{
		Filename:   filename,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	})
	logger := z.With().Caller().Timestamp().Logger()
	return &LoggerFile{
		Enabled:  true,
		Filename: filename,
		Logger:   &logger,
	}, nil
}

// Settings - Function to prepare settings for the logger
func (logFile *LoggerFile) Settings(mgr *settings.Settings) {
	log.Info().Msg("No file logging settings")
}

// Log - Function that sends JSON result/status/query logs to stdout
func (logFile *LoggerFile) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if debug {
		log.Debug().Msgf("Sending %d bytes to stdout for %s - %s", len(data), environment, uuid)
	}
	switch logType {
	case types.StatusLog:
		logFile.Status(data, environment, uuid, debug)
	case types.ResultLog:
		logFile.Result(data, environment, uuid, debug)
	}
}

// Status - Function that sends JSON status logs to stdout
func (logFile *LoggerFile) Status(data []byte, environment, uuid string, debug bool) {
	logFile.Logger.Info().Str(
		"type", types.StatusLog).Str(
		"environment", environment).Str(
		"uuid", uuid).RawJSON("data", data)
}

// Result - Function that sends JSON result logs to stdout
func (logFile *LoggerFile) Result(data []byte, environment, uuid string, debug bool) {
	logFile.Logger.Info().Str(
		"type", types.ResultLog).Str(
		"environment", environment).Str(
		"uuid", uuid).RawJSON("data", data)
}

// Query - Function that sends JSON query logs to stdout
func (logFile *LoggerFile) Query(data []byte, environment, uuid, name string, status int, debug bool) {
	logFile.Logger.Info().Str(
		"type", types.QueryLog).Str(
		"environment", environment).Str(
		"name", name).Int(
		"status", status).Str(
		"uuid", uuid).RawJSON("data", data)
}
