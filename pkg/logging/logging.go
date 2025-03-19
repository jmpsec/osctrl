package logging

import (
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultFileLog file to store logs
	DefaultFileLog = "osctrl.log"
)

// LoggerTLS will be used to handle logging for the TLS endpoint
type LoggerTLS struct {
	Logging      string
	Logger       interface{}
	AlwaysLogger *LoggerDB
	Nodes        *nodes.NodeManager
	Queries      *queries.Queries
}

// CreateLoggerTLS to instantiate a new logger for the TLS endpoint
func CreateLoggerTLS(logging, loggingFile string, s3Conf config.S3Configuration, kafkaConf config.KafkaConfiguration, loggerSame, alwaysLog bool, dbConf backend.JSONConfigurationDB, mgr *settings.Settings, nodes *nodes.NodeManager, queries *queries.Queries) (*LoggerTLS, error) {
	l := &LoggerTLS{
		Logging: logging,
		Nodes:   nodes,
		Queries: queries,
	}
	switch logging {
	case config.LoggingSplunk:
		s, err := CreateLoggerSplunk(loggingFile)
		if err != nil {
			return nil, err
		}
		s.Settings(mgr)
		l.Logger = s
	case config.LoggingGraylog:
		g, err := CreateLoggerGraylog(loggingFile)
		if err != nil {
			return nil, err
		}
		g.Settings(mgr)
		l.Logger = g
	case config.LoggingDB:
		if loggerSame {
			d, err := CreateLoggerDBConfig(dbConf)
			if err != nil {
				return nil, err
			}
			d.Settings(mgr)
			l.Logger = d
		} else {
			d, err := CreateLoggerDBFile(loggingFile)
			if err != nil {
				return nil, err
			}
			d.Settings(mgr)
			l.Logger = d
		}
	case config.LoggingStdout:
		d, err := CreateLoggerStdout()
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingFile:
		// TODO: All this should be customizable
		rotateCfg := LumberjackConfig{
			MaxSize:    25,
			MaxBackups: 5,
			MaxAge:     10,
			Compress:   true,
		}
		d, err := CreateLoggerFile(DefaultFileLog, rotateCfg)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingNone:
		d, err := CreateLoggerNone()
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingKinesis:
		d, err := CreateLoggerKinesis(loggingFile)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingS3:
		var d *LoggerS3
		var err error
		if s3Conf.Bucket != "" {
			d, err = CreateLoggerS3(s3Conf)
			if err != nil {
				return nil, err
			}
		} else {
			d, err = CreateLoggerS3File(loggingFile)
			if err != nil {
				return nil, err
			}
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingLogstash:
		d, err := CreateLoggerLogstash(loggingFile)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case config.LoggingKafka:
		k, err := CreateLoggerKafka(kafkaConf)
		if err != nil {
			return nil, err
		}
		k.Settings(mgr)
		l.Logger = k
	case config.LoggingElastic:
		e, err := CreateLoggerElastic(loggingFile)
		if err != nil {
			return nil, err
		}
		e.Settings(mgr)
		l.Logger = e
	}
	// Initialize the logger that will always log to DB
	if alwaysLog {
		always, err := CreateLoggerDBConfig(dbConf)
		if err != nil {
			return nil, err
		}
		always.Settings(mgr)
		l.AlwaysLogger = always
	}
	return l, nil
}

// Log will send status/result logs via the configured method of logging
func (logTLS *LoggerTLS) Log(logType string, data []byte, environment, uuid string, debug bool) {
	switch logTLS.Logging {
	case config.LoggingSplunk:
		l, ok := logTLS.Logger.(*LoggerSplunk)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingGraylog:
		l, ok := logTLS.Logger.(*LoggerGraylog)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingDB:
		l, ok := logTLS.Logger.(*LoggerDB)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingDB)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case config.LoggingStdout:
		l, ok := logTLS.Logger.(*LoggerStdout)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingStdout)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case config.LoggingFile:
		l, ok := logTLS.Logger.(*LoggerFile)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingFile)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case config.LoggingNone:
		l, ok := logTLS.Logger.(*LoggerNone)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingNone)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case config.LoggingKinesis:
		l, ok := logTLS.Logger.(*LoggerKinesis)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingKinesis)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingS3:
		l, ok := logTLS.Logger.(*LoggerS3)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingS3)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingKafka:
		k, ok := logTLS.Logger.(*LoggerKafka)
		if !ok {
			log.Printf("error casting logger to %s", config.LoggingKafka)
		}
		if k.Enabled {
			k.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingElastic:
		k, ok := logTLS.Logger.(*LoggerElastic)
		if !ok {
			log.Printf("error casting logger to %s", config.LoggingElastic)
		}
		if k.Enabled {
			k.Send(logType, data, environment, uuid, debug)
		}
	}
	// If logs are status, write via always logger
	if logTLS.AlwaysLogger != nil && logTLS.AlwaysLogger.Enabled && logType == types.StatusLog {
		// Check if configured logger is DB so we skip logging the same data twice
		logAlways := true
		if logTLS.Logger == config.LoggingDB {
			l, ok := logTLS.Logger.(*LoggerDB)
			if ok {
				logAlways = !sameConfigDB(*l.Database.Config, *logTLS.AlwaysLogger.Database.Config)
			}
		}
		if logAlways {
			logTLS.AlwaysLogger.Log(logType, data, environment, uuid, debug)
		}
	}
}

// QueryLog will send query result logs via the configured method of logging
func (logTLS *LoggerTLS) QueryLog(logType string, data []byte, environment, uuid, name string, status int, debug bool) {
	switch logTLS.Logging {
	case config.LoggingSplunk:
		l, ok := logTLS.Logger.(*LoggerSplunk)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingGraylog:
		l, ok := logTLS.Logger.(*LoggerGraylog)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingDB:
		l, ok := logTLS.Logger.(*LoggerDB)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingDB)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case config.LoggingStdout:
		l, ok := logTLS.Logger.(*LoggerStdout)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingStdout)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case config.LoggingFile:
		l, ok := logTLS.Logger.(*LoggerFile)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingFile)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case config.LoggingNone:
		l, ok := logTLS.Logger.(*LoggerNone)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingNone)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case config.LoggingKinesis:
		l, ok := logTLS.Logger.(*LoggerKinesis)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingKinesis)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingS3:
		l, ok := logTLS.Logger.(*LoggerS3)
		if !ok {
			log.Error().Msgf("error casting logger to %s", config.LoggingS3)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case config.LoggingKafka:
		k, ok := logTLS.Logger.(*LoggerKafka)
		if !ok {
			log.Printf("error casting logger to %s", config.LoggingKafka)
		}
		if k.Enabled {
			k.Send(logType, data, environment, uuid, debug)
		}
	}
	// Always log results to DB if always logger is enabled
	if logTLS.AlwaysLogger != nil && logTLS.AlwaysLogger.Enabled {
		// Check if configured logger is DB so we skip logging the same data twice
		logAlways := true
		if logTLS.Logger == config.LoggingDB {
			l, ok := logTLS.Logger.(*LoggerDB)
			if ok {
				logAlways = !sameConfigDB(*l.Database.Config, *logTLS.AlwaysLogger.Database.Config)
			}
		}
		if logAlways {
			logTLS.AlwaysLogger.Query(data, environment, uuid, name, status, debug)
		}
	}
}
