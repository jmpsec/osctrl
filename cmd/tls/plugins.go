package main

import (
	"fmt"
	"path/filepath"
	"plugin"
)

// Variables for plugin functions
var (
	logsDispatcher func(logging, logType string, params ...interface{})
)

// Function to load logging dispatcher plugin
func loadLoggingDispatcherPlugin() error {
	plugins, err := filepath.Glob("plugins/logging_dispatcher_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	symbolLogsDispatcher, err := p.Lookup("LogsDispatcher")
	if err != nil {
		return err
	}
	var ok bool
	logsDispatcher, ok = symbolLogsDispatcher.(func(logging, logType string, params ...interface{}))
	if !ok {
		return fmt.Errorf("Plugin has no 'LogsDispatcher' function")
	}
	return nil
}

/*
// Function to load Postgres logging plugin
func loadPostgresPlugin() error {
	plugins, err := filepath.Glob("plugins/postgres_logging_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	symbolPostgresSend, err := p.Lookup("PostgresSend")
	if err != nil {
		return err
	}
	var ok bool
	postgresSend, ok = symbolPostgresSend.(func(*gorm.DB, []byte, string, string, string, string, int, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'PostgresSend' function")
	}
	symbolPostgresLog, err := p.Lookup("PostgresLog")
	if err != nil {
		return err
	}
	postgresLog, ok = symbolPostgresLog.(func(*gorm.DB, []byte, string, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'PostgresLog' function")
	}
	symbolPostgresQuery, err := p.Lookup("PostgresQuery")
	if err != nil {
		return err
	}
	postgresQuery, ok = symbolPostgresQuery.(func(*gorm.DB, []byte, string, string, string, int, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'PostgresQuery' function")
	}
	return nil
}

// Function to load Graylog logging plugin
func loadGraylogPlugin() error {
	plugins, err := filepath.Glob("plugins/graylog_logging_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	symbolGraylogSend, err := p.Lookup("GraylogSend")
	if err != nil {
		return err
	}
	var ok bool
	graylogSend, ok = symbolGraylogSend.(func([]byte, string, string, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'GraylogSend' function")
	}
	return nil
}

// Function to load Splunk logging plugin
func loadSplunkPlugin() error {
	plugins, err := filepath.Glob("plugins/splunk_logging_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	symbolSplunkSend, err := p.Lookup("SplunkSend")
	if err != nil {
		return err
	}
	var ok bool
	splunkSend, ok = symbolSplunkSend.(func([]byte, string, string, string, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'SplunkSend' function")
	}
	return nil
}
*/
