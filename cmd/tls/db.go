package main

import (
	"fmt"
	"log"
	"time"

	"github.com/javuto/osctrl/pkg/carves"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/spf13/viper"

	"github.com/jinzhu/gorm"
)

const (
	// DB configuration file
	dbConfigurationFile string = "config/db.json"
)

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Function to load the DB configuration file and assign to variables
func loadDBConfiguration(file string) (JSONConfigurationDB, error) {
	var config JSONConfigurationDB
	log.Printf("Loading %s", file)
	// Load file and read config
	viper.SetConfigFile(file)
	err := viper.ReadInConfig()
	if err != nil {
		return config, err
	}
	// Backend values
	dbRaw := viper.Sub("db")
	err = dbRaw.Unmarshal(&config)
	if err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// Get PostgreSQL DB using GORM
func getDB() *gorm.DB {
	// Load DB configuration
	config, err := loadDBConfiguration(dbConfigurationFile)
	if err != nil {
		log.Fatalf("Error loading DB configuration %s", err)
	}
	t := "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable"
	postgresDSN := fmt.Sprintf(
		t, config.Host, config.Port, config.Name, config.Username, config.Password)
	db, err := gorm.Open("postgres", postgresDSN)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	// Performance settings for DB access
	db.DB().SetMaxIdleConns(20)
	db.DB().SetMaxOpenConns(100)
	db.DB().SetConnMaxLifetime(time.Second * 30)

	return db
}

// Automigrate of tables
func automigrateDB() error {
	var err error
	// table osquery_nodes
	err = db.AutoMigrate(nodes.OsqueryNode{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_nodes): %v", err)
	}
	// table archive_osquery_nodes
	err = db.AutoMigrate(nodes.ArchiveOsqueryNode{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (archive_osquery_nodes): %v", err)
	}
	// table node_history_ipaddress
	err = db.AutoMigrate(nodes.NodeHistoryIPAddress{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_ipaddress): %v", err)
	}
	// table node_history_hostname
	err = db.AutoMigrate(nodes.NodeHistoryHostname{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_hostname): %v", err)
	}
	// table node_history_localname
	err = db.AutoMigrate(nodes.NodeHistoryLocalname{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_localname): %v", err)
	}
	// table node_history_username
	err = db.AutoMigrate(nodes.NodeHistoryUsername{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (node_history_username): %v", err)
	}
	// table setting_values
	err = db.AutoMigrate(settings.SettingValue{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (setting_values): %v", err)
	}
	// table carved_files
	err = db.AutoMigrate(carves.CarvedFile{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (carved_files): %v", err)
	}
	// table carved_blocks
	err = db.AutoMigrate(carves.CarvedBlock{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (carved_blocks): %v", err)
	}
	return nil
}
