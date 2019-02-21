package main

import (
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

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

// Automigrate of tables
func automigrateDB() error {
	var err error
	// table tls_contexts
	err = db.AutoMigrate(TLSContext{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (tls_contexts): %v", err)
	}
	// table admin_users
	err = db.AutoMigrate(AdminUser{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (admin_users): %v", err)
	}
	// table configuration_values
	err = db.AutoMigrate(ConfigurationValue{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (configuration_values): %v", err)
	}
	return nil
}
