package main

import (
	"log"

	"github.com/jinzhu/gorm"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
)

// Variables for configuration from JSON files
var (
	graylogCfg   GraylogConfiguration
	graylogReady bool
	splunkCfg    SlunkConfiguration
	splunkReady  bool
	dbReady      bool
)

// Initialization of the plugin
func init() {
	var err error
	// Check if Graylog is ready to load
	graylogCfg, err = loadGraylogConfiguration()
	if err != nil {
		graylogReady = false
	} else {
		if err := loadGraylogPlugin(); err != nil {
			graylogReady = false
			log.Printf("Failed to load graylog plugin - %v", err)
		} else {
			graylogReady = true
		}
	}
	// Check if Splunk is ready to load
	splunkCfg, err = loadSplunkConfiguration()
	if err != nil {
		splunkReady = false
	} else {
		if err := loadSplunkPlugin(); err != nil {
			splunkReady = false
			log.Printf("Failed to load splunk plugin - %v", err)
		} else {
			splunkReady = true
		}
	}
	// Loading DB plugin regardless
	err = loadDBPlugin()
	if err != nil {
		dbReady = false
		log.Printf("Failed to load db plugin - %v", err)
	} else {
		dbReady = true
	}
}

// LogsDispatcher - Main method for dispatching logs
func LogsDispatcher(logging, logType string, params ...interface{}) {
	db := params[0].(*gorm.DB)
	data := params[1].([]byte)
	environment := params[2].(string)
	uuid := params[3].(string)
	switch logging {
	case settings.LoggingGraylog:
		if graylogReady {
			var debug bool
			if logType == types.QueryLog {
				debug = params[6].(bool)
			} else {
				debug = params[4].(bool)
			}
			graylogSend(logType, data, environment, uuid, graylogCfg.URL, debug)
		} else {
			log.Printf("Logging with %s isn't ready [%s] - Dropping %d bytes", graylogName, graylogCfg.URL, len(data))
		}
	case settings.LoggingSplunk:
		if splunkReady {
			var debug bool
			if logType == types.QueryLog {
				debug = params[6].(bool)
			} else {
				debug = params[4].(bool)
			}
			splunkSend(logType, data, environment, uuid, splunkCfg.URL, splunkCfg.Token, debug)
		} else {
			log.Printf("Logging with %s isn't ready [%s] - Dropping %d bytes", splunkName, splunkCfg.URL, len(data))
		}
	case settings.LoggingDB:
		if dbReady {
			if logType == types.QueryLog {
				name := params[4].(string)
				status := params[5].(int)
				debug := params[6].(bool)
				dbQuery(db, data, environment, uuid, name, status, debug)
			} else {
				debug := params[4].(bool)
				dbLog(logType, db, data, environment, uuid, debug)
			}
		} else {
			log.Printf("Logging with %s isn't ready - Dropping %d bytes", dbName, len(data))
		}
	}
}
