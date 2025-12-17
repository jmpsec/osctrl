package logging

import (
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// LoggerFile will be used to log data using external file
type LoggerFile struct {
	Enabled  bool
	Filename string
	Logger   *zerolog.Logger
}

// CreateLoggerFile to initialize the logger
func CreateLoggerFile(cfg *config.LocalLogger) (*LoggerFile, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	z := zerolog.New(&lumberjack.Logger{
		Filename:   cfg.FilePath,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	})
	logger := z.With().Caller().Timestamp().Logger()
	return &LoggerFile{
		Enabled:  true,
		Filename: cfg.FilePath,
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
