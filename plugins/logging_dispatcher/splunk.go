package main

import (
	"fmt"
	"log"
	"path/filepath"
	"plugin"

	"github.com/spf13/viper"
)

const (
	// Splunk value
	splunkName string = "splunk"
	// Splunk configuration file
	splunkConfigFile string = "config/" + splunkName + ".json"
)

// SlunkConfiguration to hold all splunk configuration values
type SlunkConfiguration struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// Function to load the Splunk configuration from JSON file
func loadSplunkConfiguration() (SlunkConfiguration, error) {
	var _splunkCfg SlunkConfiguration
	log.Printf("Loading %s", splunkConfigFile)
	// Load file and read config
	viper.SetConfigFile(splunkConfigFile)
	err := viper.ReadInConfig()
	if err != nil {
		return _splunkCfg, err
	}
	cfgRaw := viper.Sub(splunkName)
	err = cfgRaw.Unmarshal(&_splunkCfg)
	if err != nil {
		return _splunkCfg, err
	}
	// No errors!
	return _splunkCfg, nil
}

var (
	splunkSend func(string, []byte, string, string, string, string, bool)
)

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
	splunkSend, ok = symbolSplunkSend.(func(string, []byte, string, string, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'SplunkSend' function")
	}
	return nil
}
