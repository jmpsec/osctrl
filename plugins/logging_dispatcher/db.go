package main

import (
	"fmt"
	"path/filepath"
	"plugin"

	"github.com/jinzhu/gorm"
)

const (
	// Graylog value
	dbName string = "DB"
)

var (
	dbLog   func(string, *gorm.DB, []byte, string, string, bool)
	dbQuery func(*gorm.DB, []byte, string, string, string, int, bool)
)

// Function to load DB logging plugin
func loadDBPlugin() error {
	plugins, err := filepath.Glob("plugins/db_logging_plugin.so")
	if err != nil {
		return err
	}
	p, err := plugin.Open(plugins[0])
	if err != nil {
		return err
	}
	symbolDBLog, err := p.Lookup("DBLog")
	if err != nil {
		return err
	}
	var ok bool
	dbLog, ok = symbolDBLog.(func(string, *gorm.DB, []byte, string, string, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'DBLog' function")
	}
	symbolDBQuery, err := p.Lookup("DBQuery")
	if err != nil {
		return err
	}
	dbQuery, ok = symbolDBQuery.(func(*gorm.DB, []byte, string, string, string, int, bool))
	if !ok {
		return fmt.Errorf("Plugin has no 'DBQuery' function")
	}
	return nil
}
