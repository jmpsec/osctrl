package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"

	"github.com/jinzhu/gorm"

	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
)

// Function to load the DB configuration file and assign to variables
func loadDBConfiguration(file string) (types.JSONConfigurationDB, error) {
	var config types.JSONConfigurationDB
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
func getDB(config types.JSONConfigurationDB) *gorm.DB {
	t := "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable"
	postgresDSN := fmt.Sprintf(
		t, config.Host, config.Port, config.Name, config.Username, config.Password)
	db, err := gorm.Open("postgres", postgresDSN)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	// Performance settings for DB access
	// FIXME retrieve this from JSON file instead of hardcoded
	db.DB().SetMaxIdleConns(5)
	db.DB().SetMaxOpenConns(20)
	db.DB().SetConnMaxLifetime(time.Second * 5)
	return db
}
