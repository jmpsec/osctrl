package main

import (
	"fmt"
	"log"
	"time"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/users"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/spf13/viper"
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
	dbConfig, err := loadDBConfiguration(dbConfigurationFile)
	if err != nil {
		log.Fatalf("Error loading DB configuration %s", err)
	}
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
	// table distributed_queries
	err = db.AutoMigrate(queries.DistributedQuery{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_queries): %v", err)
	}
	// table distributed_query_executions
	err = db.AutoMigrate(queries.DistributedQueryExecution{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_query_executions): %v", err)
	}
	// table distributed_query_targets
	err = db.AutoMigrate(queries.DistributedQueryTarget{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (distributed_query_targets): %v", err)
	}
	// table osquery_status_data
	err = db.AutoMigrate(OsqueryStatusData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_status_data): %v", err)
	}
	// table osquery_result_data
	err = db.AutoMigrate(OsqueryResultData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_result_data): %v", err)
	}
	// table osquery_query_data
	err = db.AutoMigrate(OsqueryQueryData{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (osquery_query_data): %v", err)
	}
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
	// table user_sessions
	err = db.AutoMigrate(&UserSession{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (user_sessions): %v", err)
	}

	return nil
}
