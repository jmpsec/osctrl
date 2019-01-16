package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

const (
	// Service configuration file
	configurationFile = "config/tls.json"
)

// Global variables
var (
	db       *gorm.DB
	dbConfig JSONConfigurationBackend
)

// Function to load the configuration file and assign to variables
func loadConfiguration() error {
	log.Printf("Loading %s", configurationFile)
	// Load file and read config
	viper.SetConfigFile(configurationFile)
	err := viper.ReadInConfig()
	if err != nil {
		return err
	}
	// Backend values
	dbRaw := viper.Sub("db")
	err = dbRaw.Unmarshal(&dbConfig)
	if err != nil {
		return err
	}
	// No errors!
	return nil
}

// Initialization code
func init() {
	// Logging flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Load configuration
	err := loadConfiguration()
	if err != nil {
		log.Fatalf("Error loading configuration %s", err)
	}
}

// Go go!
func main() {
	// Database handler
	db = getDB()
	// Close when exit
	defer db.Close()

	log.Println("This is it")
}

// Get PostgreSQL DB using GORM
func getDB() *gorm.DB {
	t := "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable"
	postgresDSN := fmt.Sprintf(
		t, dbConfig.Host, dbConfig.Port, dbConfig.Name, dbConfig.Username, dbConfig.Password)
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
