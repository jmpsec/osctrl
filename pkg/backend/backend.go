package backend

import (
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/spf13/viper"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	// DBString to format connection string to database for postgres
	PostgresDBString = "host=%s port=%s dbname=%s user=%s password=%s sslmode=%s"
	// MySQLDBString to format connection string for MySQL
	MySQLDBString = "%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local"
	// DBKey to identify the configuration JSON key
	DBKey = "db"
	// Database types
	DBTypePostgres = "postgres"
	DBTypeMySQL    = "mysql"
	DBTypeSQLite   = "sqlite"
)

// DBManager have access to backend
type DBManager struct {
	Conn   *gorm.DB
	Config *config.YAMLConfigurationDB
	DSN    string
}

// PrepareDSN to generate DB connection string
func PrepareDSN(config config.YAMLConfigurationDB) string {
	switch config.Type {
	case DBTypePostgres:
		return fmt.Sprintf(
			PostgresDBString, config.Host, config.Port, config.Name, config.Username, config.Password, config.SSLMode)
	case DBTypeMySQL:
		return fmt.Sprintf(
			MySQLDBString, config.Username, config.Password, config.Host, config.Port, config.Name)
	case DBTypeSQLite:
		return config.FilePath
	default:
		// Default to postgres if not specified
		return fmt.Sprintf(
			PostgresDBString, config.Host, config.Port, config.Name, config.Username, config.Password, config.SSLMode)
	}
}

// GetDB to get DB using GORM based on the configured driver
func (db *DBManager) GetDB() (*gorm.DB, error) {
	var dbConn *gorm.DB
	var err error

	// Select the appropriate driver based on database type
	switch db.Config.Type {
	case DBTypePostgres:
		dbConn, err = gorm.Open(postgres.Open(db.DSN), &gorm.Config{})
	case DBTypeMySQL:
		dbConn, err = gorm.Open(mysql.Open(db.DSN), &gorm.Config{})
	case DBTypeSQLite:
		dbConn, err = gorm.Open(sqlite.Open(db.DSN), &gorm.Config{})
	default:
		// Default to postgres if type not specified
		dbConn, err = gorm.Open(postgres.Open(db.DSN), &gorm.Config{})
	}
	if err != nil {
		return nil, err
	}
	sqlDB, err := dbConn.DB()
	if err != nil {
		return nil, err
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, err
	}
	// Performance settings for DB access
	sqlDB.SetMaxIdleConns(db.Config.MaxIdleConns)
	sqlDB.SetMaxOpenConns(db.Config.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Second * time.Duration(db.Config.ConnMaxLifetime))
	return dbConn, nil
}

// Check to verify if connection is open and ready
func (db *DBManager) Check() error {
	sqlDB, err := db.Conn.DB()
	if err != nil {
		return err
	}
	if err := sqlDB.Ping(); err != nil {
		return err
	}
	return nil
}

// LoadDBManagerFile - Function to load DB configuration from YAML file
func LoadDBManagerFile(dbConfigFile string) (*config.YAMLConfigurationDB, error) {
	var cfg config.YAMLConfigurationDB
	// Load file and read config
	viper.SetConfigFile(dbConfigFile)
	viper.SetConfigType(config.YAMLConfigType)
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	// Extract the correct section
	viperSub := viper.Sub(config.YAMLDBType)
	if viperSub == nil {
		return nil, fmt.Errorf("no '%s' section found in configuration file", config.YAMLDBType)
	}
	// Unmarshal into struct
	if err := viperSub.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// CreateDBManagerFile to load values from YAML file and initialize the DB struct
func CreateDBManagerFile(dbConfigFile string) (*DBManager, error) {
	cfg, err := LoadDBManagerFile(dbConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load DB configuration file - %w", err)
	}
	return CreateDBManager(cfg)
}

// CreateDBManager to initialize the DB struct
func CreateDBManager(dbConfig *config.YAMLConfigurationDB) (*DBManager, error) {
	db := &DBManager{}
	db.Config = dbConfig
	db.DSN = PrepareDSN(*dbConfig)
	dbConn, err := db.GetDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get DB - %w", err)
	}
	db.Conn = dbConn
	return db, nil
}
