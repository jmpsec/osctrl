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
