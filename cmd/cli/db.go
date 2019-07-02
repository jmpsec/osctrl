package main

import (
	"fmt"
	"log"
	"time"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/users"

	"github.com/jinzhu/gorm"

	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
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
func getDB(config JSONConfigurationDB) *gorm.DB {
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
	// table tls_environments
	err = db.AutoMigrate(environments.TLSEnvironment{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (tls_environments): %v", err)
	}
	// table admin_users
	err = db.AutoMigrate(users.AdminUser{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (admin_users): %v", err)
	}
	// table setting_values
	err = db.AutoMigrate(settings.SettingValue{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (setting_values): %v", err)
	}
	return nil
}
