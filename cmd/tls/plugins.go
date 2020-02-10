package main

import (
	"fmt"
	"log"
	"path/filepath"
	"plugin"

	"github.com/jmpsec/osctrl/pkg/settings"
)

// Variables for plugin functions
var (
	logsDispatcher func(logging, logType string, params ...interface{})
	logsSettings   func(logging string, mgr *settings.Settings, debug bool)
)

// Loading plugins
func loadPlugins() error {
	log.Println("Loading logging dispatcher plugin")
	if err := loadLoggingDispatcherPlugin(); err != nil {
		return err
	}
	return nil
}

// Function to load logging dispatcher plugin
func loadLoggingDispatcherPlugin() error {
	var ok bool
	plugins, err := filepath.Glob("/osctrl-tls/bin/logging_dispatcher_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	// Load symbol for dispatcher
	symbolLogsDispatcher, err := p.Lookup("LogsDispatcher")
	if err != nil {
		return err
	}
	logsDispatcher, ok = symbolLogsDispatcher.(func(logging, logType string, params ...interface{}))
	if !ok {
		return fmt.Errorf("Plugin has no 'LogsDispatcher' function")
	}
	// Load symbol for settings
	symbolLogsSettings, err := p.Lookup("LogsSettings")
	if err != nil {
		return err
	}
	logsSettings, ok = symbolLogsSettings.(func(logging string, mgr *settings.Settings, debug bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'LogsSettings' function")
	}
	return nil
}
