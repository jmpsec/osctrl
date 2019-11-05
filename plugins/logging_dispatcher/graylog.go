package main

import (
	"fmt"
	"log"
	"path/filepath"
	"plugin"

	"github.com/spf13/viper"
)

const (
	// Graylog value
	graylogName string = "graylog"
	// Graylog configuration file
	graylogConfigFile string = "config/" + graylogName + ".json"
)

// GraylogConfiguration to hold all graylog configuration values
type GraylogConfiguration struct {
	URL     string `json:"url"`
	Queries string `json:"queries"`
	Status  string `json:"status"`
	Results string `json:"results"`
}

// Function to load the Graylog configuration from JSON file
func loadGraylogConfiguration() (GraylogConfiguration, error) {
	var _graylogCfg GraylogConfiguration
	log.Printf("Loading %s", graylogConfigFile)
	// Load file and read config
	viper.SetConfigFile(graylogConfigFile)
	err := viper.ReadInConfig()
	if err != nil {
		return _graylogCfg, err
	}
	cfgRaw := viper.Sub(graylogName)
	err = cfgRaw.Unmarshal(&_graylogCfg)
	if err != nil {
		return _graylogCfg, err
	}
	// No errors!
	return _graylogCfg, nil
}

var (
	graylogSend func(string, []byte, string, string, string, bool)
)

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
	graylogSend, ok = symbolGraylogSend.(func(string, []byte, string, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'GraylogSend' function")
	}
	return nil
}
