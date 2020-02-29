package logging

import (
	"github.com/jmpsec/osctrl/settings"
)

// LoggerTLS will be used to handle logging for the TLS endpoint
type LoggerTLS struct {
	DB      *LoggerDB
	Graylog *LoggerGraylog
	Splunk  *LoggerSplunk
	Logging string
}

// CreateLoggerTLS to instantiate a new logger for the TLS endpoint
func CreateLoggerTLS(logging string, mgr *settings.Settings) (*LoggerTLS, error) {
	l := &LoggerTLS{
		DB:      &LoggerDB{},
		Splunk:  &LoggerSplunk{},
		Logging: logging,
		Graylog: &LoggerGraylog{},
	}
	switch logging {
	case settings.LoggingSplunk:
		s, err := CreateLoggerSplunk()
		if err != nil {
			return nil, err
		}
		s.Settings(mgr)
		l.Splunk = s
	case settings.LoggingGraylog:
		g, err := CreateLoggerGraylog()
		if err != nil {
			return nil, err
		}
		g.Settings(mgr)
		l.Graylog = g
	}
	// Initialize the DB logger anyway
	d, err := CreateLoggerDB()
	if err != nil {
		return nil, err
	}
	d.Settings(mgr)
	l.DB = d
	return l, nil
}

// Log will send status/result logs via the configured method of logging
func (logTLS *LoggerTLS) Log(logType string, data []byte, environment, uuid string, debug bool) {
	switch logTLS.Logging {
	case settings.LoggingSplunk:
		if logTLS.Splunk.Enabled {
			logTLS.Splunk.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		if logTLS.Graylog.Enabled {
			logTLS.Graylog.Send(logType, data, environment, uuid, debug)
		}
	// TODO: Log to db to keep 24 hours of logs locally
	// https://github.com/jmpsec/osctrl/issues/19
	case settings.LoggingDB:
		if logTLS.DB.Enabled {
			logTLS.DB.Log(logType, data, environment, uuid, debug)
		}
	}
}

// LogQuery will send query result logs via the configured method of logging
func (logTLS *LoggerTLS) QueryLog(logType string, data []byte, environment, uuid, name string, status int, debug bool) {
	switch logTLS.Logging {
	case settings.LoggingSplunk:
		if logTLS.Splunk.Enabled {
			logTLS.Splunk.Send(logType, data, environment, uuid, debug)
		}
	case settings.LoggingGraylog:
		if logTLS.Graylog.Enabled {
			logTLS.Graylog.Send(logType, data, environment, uuid, debug)
		}
	}
	// Logging to DB happens anyway
	if logTLS.DB.Enabled {
		logTLS.DB.Query(data, environment, uuid, name, status, debug)
	}
}
