package main

import (
	"fmt"
	"log"
	"time"

	"github.com/javuto/osctrl/configuration"
	"github.com/javuto/osctrl/context"
	"github.com/javuto/osctrl/nodes"
	"github.com/javuto/osctrl/queries"
	"github.com/javuto/osctrl/users"
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
	// table geo_location_ipaddress
	err = db.AutoMigrate(nodes.GeoLocationIPAddress{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (geo_location_ipaddress): %v", err)
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
	// table tls_contexts
	err = db.AutoMigrate(context.TLSContext{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (tls_contexts): %v", err)
	}
	// table admin_users
	err = db.AutoMigrate(users.AdminUser{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (admin_users): %v", err)
	}
	// table config_values
	err = db.AutoMigrate(configuration.ConfigValue{}).Error
	if err != nil {
		log.Fatalf("Failed to AutoMigrate table (config_values): %v", err)
	}
	return nil
}
