package logging

import (
	"log"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/types"
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
func CreateLoggerTLS(logging, loggingFile string, s3Conf types.S3Configuration, kafkaConf types.KafkaConfiguration, loggerSame, alwaysLog bool, dbConf backend.JSONConfigurationDB, mgr *settings.Settings, nodes *nodes.NodeManager, queries *queries.Queries) (*LoggerTLS, error) {
	l := &LoggerTLS{
		Logging: logging,
		Nodes:   nodes,
		Queries: queries,
	}
	switch logging {
	case settings.LoggingSplunk:
		s, err := CreateLoggerSplunk(loggingFile)
		if err != nil {
			return nil, err
		}
		s.Settings(mgr)
		l.Logger = s
	case settings.LoggingGraylog:
		g, err := CreateLoggerGraylog(loggingFile)
		if err != nil {
			return nil, err
		}
		g.Settings(mgr)
		l.Logger = g
	case settings.LoggingDB:
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
	case settings.LoggingStdout:
		d, err := CreateLoggerStdout()
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case settings.LoggingFile:
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
	case settings.LoggingNone:
		d, err := CreateLoggerNone()
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case settings.LoggingKinesis:
		d, err := CreateLoggerKinesis(loggingFile)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case settings.LoggingS3:
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
	case settings.LoggingLogstash:
		d, err := CreateLoggerLogstash(loggingFile)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
	case settings.LoggingKafka:
		k, err := CreateLoggerKafka(kafkaConf)
		if err != nil {
			return nil, err
		}
		k.Settings(mgr)
		l.Logger = k
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
	case settings.LoggingSplunk:
		l, ok := logTLS.Logger.(*LoggerSplunk)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		l, ok := logTLS.Logger.(*LoggerGraylog)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingDB:
		l, ok := logTLS.Logger.(*LoggerDB)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingDB)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingStdout:
		l, ok := logTLS.Logger.(*LoggerStdout)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingStdout)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingFile:
		l, ok := logTLS.Logger.(*LoggerFile)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingFile)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingNone:
		l, ok := logTLS.Logger.(*LoggerNone)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingNone)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingKinesis:
		l, ok := logTLS.Logger.(*LoggerKinesis)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingKinesis)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingS3:
		l, ok := logTLS.Logger.(*LoggerS3)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingS3)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingKafka:
		k, ok := logTLS.Logger.(*LoggerKafka)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingKafka)
		}
		if k.Enabled {
			k.Send(logType, data, environment, uuid, debug)
		}
	}
	// If logs are status, write via always logger
	if logTLS.AlwaysLogger != nil && logTLS.AlwaysLogger.Enabled && logType == types.StatusLog {
		// Check if configured logger is DB so we skip logging the same data twice
		logAlways := true
		if logTLS.Logger == settings.LoggingDB {
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
	case settings.LoggingSplunk:
		l, ok := logTLS.Logger.(*LoggerSplunk)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		l, ok := logTLS.Logger.(*LoggerGraylog)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingDB:
		l, ok := logTLS.Logger.(*LoggerDB)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingDB)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingStdout:
		l, ok := logTLS.Logger.(*LoggerStdout)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingStdout)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingFile:
		l, ok := logTLS.Logger.(*LoggerFile)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingFile)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingNone:
		l, ok := logTLS.Logger.(*LoggerNone)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingNone)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingKinesis:
		l, ok := logTLS.Logger.(*LoggerKinesis)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingKinesis)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingS3:
		l, ok := logTLS.Logger.(*LoggerS3)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingS3)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingKafka:
		k, ok := logTLS.Logger.(*LoggerKafka)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingKafka)
		}
		if k.Enabled {
			k.Send(logType, data, environment, uuid, debug)
		}
	}
	// Always log results to DB if always logger is enabled
	if logTLS.AlwaysLogger != nil && logTLS.AlwaysLogger.Enabled {
		// Check if configured logger is DB so we skip logging the same data twice
		logAlways := true
		if logTLS.Logger == settings.LoggingDB {
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
