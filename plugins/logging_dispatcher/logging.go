package main

import (
	"log"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jinzhu/gorm"
)

const (
	// Graylog enabled
	graylogOn bool = false
	// Splunk enabled
	splunkOn bool = false
	// DB enabled
	dbOn bool = true
)

// Variables for configuration from JSON files
var (
	graylogCfg GraylogConfiguration
	splunkCfg  SlunkConfiguration
)

// Initialization of the plugin
func init() {
	var err error
	if graylogOn {
		graylogCfg, err = loadGraylogConfiguration()
		if err != nil {
			log.Fatalf("Failed to load graylog json - %v", err)
		}
	}
	if splunkOn {
		splunkCfg, err = loadSplunkConfiguration()
		if err != nil {
			log.Fatalf("Failed to load splunk json - %v", err)
		}
	}
	if dbOn {
		err = loadDBPlugin()
		if err != nil {
			log.Fatalf("Failed to load db plugin - %v", err)
		}
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
		debug := params[4].(bool)
		graylogSend(logType, data, environment, uuid, graylogCfg.URL, debug)
	case settings.LoggingSplunk:
		debug := params[4].(bool)
		splunkSend(logType, data, environment, uuid, splunkCfg.URL, splunkCfg.Token, debug)
	case settings.LoggingDB:
		if logType == types.QueryLog {
			name := params[4].(string)
			status := params[5].(int)
			debug := params[6].(bool)
			dbQuery(db, data, environment, uuid, name, status, debug)
		} else {
			debug := params[4].(bool)
			dbLog(logType, db, data, environment, uuid, debug)
		}
	}
}
