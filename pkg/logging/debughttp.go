package logging

import (
	"github.com/rs/zerolog"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	// Default time format for loggers
	LoggerTimeFormat string = "2006-01-02T15:04:05.999Z07:00"
)

// CreateDebugHTTP to initialize the debug HTTP logger
func CreateDebugHTTP(filename string, cfg LumberjackConfig) (*zerolog.Logger, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	z := zerolog.New(&lumberjack.Logger{
		Filename:   filename,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	})
	logger := z.With().Caller().Timestamp().Logger()
	return &logger, nil
}
