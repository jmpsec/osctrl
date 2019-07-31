package main

import (
	"fmt"
	"log"
	"time"

	"github.com/spf13/viper"

	"github.com/jinzhu/gorm"

	"github.com/jmpsec/osctrl/pkg/types"
)

const (
	// DB configuration file
	dbConfigurationFile string = "config/db.json"
)

// Function to load the DB configuration file and assign to variables
func loadDBConfiguration(file string) (types.JSONConfigurationDB, error) {
	var config types.JSONConfigurationDB
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
	// FIXME get these from JSON
	db.DB().SetMaxIdleConns(20)
	db.DB().SetMaxOpenConns(100)
	db.DB().SetConnMaxLifetime(time.Second * 30)

	return db
}
