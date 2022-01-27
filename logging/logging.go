package logging

import (
	"log"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
)

// LoggerTLS will be used to handle logging for the TLS endpoint
type LoggerTLS struct {
	Logging string
	Logger  interface{}
	Nodes   *nodes.NodeManager
	Queries *queries.Queries
}

// CreateLoggerTLS to instantiate a new logger for the TLS endpoint
func CreateLoggerTLS(logging, loggingFile string, mgr *settings.Settings, nodes *nodes.NodeManager, queries *queries.Queries) (*LoggerTLS, error) {
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
		d, err := CreateLoggerDB(loggingFile)
		if err != nil {
			return nil, err
		}
		d.Settings(mgr)
		l.Logger = d
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
			MaxSize: 25,
			MaxBackups: 5,
			MaxAge: 10,
			Compress: true,
		}
		d, err := CreateLoggerFile("osctrl.log", rotateCfg)
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
	}
	// Initialize the DB logger anyway
	return l, nil
}

// Log will send status/result logs via the configured method of logging
func (logTLS *LoggerTLS) Log(logType string, data []byte, environment, uuid string, debug bool) {
	switch logTLS.Logging {
	case settings.LoggingSplunk:
		l, ok := logTLS.Logger.(LoggerSplunk)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		l, ok := logTLS.Logger.(LoggerGraylog)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingDB:
		l, ok := logTLS.Logger.(LoggerDB)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingDB)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingStdout:
		l, ok := logTLS.Logger.(LoggerStdout)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingStdout)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingFile:
		l, ok := logTLS.Logger.(LoggerFile)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingFile)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	case settings.LoggingNone:
		l, ok := logTLS.Logger.(LoggerNone)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingNone)
		}
		if l.Enabled {
			l.Log(logType, data, environment, uuid, debug)
		}
	}
}

// QueryLog will send query result logs via the configured method of logging
func (logTLS *LoggerTLS) QueryLog(logType string, data []byte, environment, uuid, name string, status int, debug bool) {
	switch logTLS.Logging {
	case settings.LoggingSplunk:
		l, ok := logTLS.Logger.(LoggerSplunk)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingSplunk)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		l, ok := logTLS.Logger.(LoggerGraylog)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingGraylog)
		}
		if l.Enabled {
			l.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingDB:
		l, ok := logTLS.Logger.(LoggerDB)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingDB)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingStdout:
		l, ok := logTLS.Logger.(LoggerStdout)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingStdout)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingFile:
		l, ok := logTLS.Logger.(LoggerFile)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingFile)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	case settings.LoggingNone:
		l, ok := logTLS.Logger.(LoggerNone)
		if !ok {
			log.Printf("error casting logger to %s", settings.LoggingNone)
		}
		if l.Enabled {
			l.Query(data, environment, uuid, name, status, debug)
		}
	}
}
