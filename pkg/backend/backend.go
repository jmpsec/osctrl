package backend

import (
	"fmt"
	"time"

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
	Config *JSONConfigurationDB
	DSN    string
}

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Type            string `json:"type"` // Database type: postgres, mysql, sqlite
	Host            string `json:"host"`
	Port            string `json:"port"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	SSLMode         string `json:"sslmode"`
	MaxIdleConns    int    `json:"maxIdleConns"`
	MaxOpenConns    int    `json:"maxOpenConns"`
	ConnMaxLifetime int    `json:"connMaxLifetime"`
	ConnRetry       int    `json:"connRetry"`
	FilePath        string `json:"filePath"` // Used for SQLite
}

// LoadConfiguration to load the DB configuration file and assign to variables
func LoadConfiguration(file, key string) (JSONConfigurationDB, error) {
	var config JSONConfigurationDB
	// Load file and read config
	viper.SetConfigFile(file)
	if err := viper.ReadInConfig(); err != nil {
		return config, err
	}
	// Backend values
	dbRaw := viper.Sub(key)
	if dbRaw == nil {
		return config, fmt.Errorf("JSON key %s not found in %s", key, file)
	}
	if err := dbRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// PrepareDSN to generate DB connection string
func PrepareDSN(config JSONConfigurationDB) string {
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

// CreateDBManager to initialize the DB struct
func CreateDBManagerFile(file string) (*DBManager, error) {
	dbConfig, err := LoadConfiguration(file, DBKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to load DB configuration - %w", err)
	}
	return CreateDBManager(dbConfig)
}

// CreateDBManager to initialize the DB struct
func CreateDBManager(dbConfig JSONConfigurationDB) (*DBManager, error) {
	db := &DBManager{}
	db.Config = &dbConfig
	db.DSN = PrepareDSN(dbConfig)
	dbConn, err := db.GetDB()
	if err != nil {
		return nil, fmt.Errorf("Failed to get DB - %w", err)
	}
	db.Conn = dbConn
	return db, nil
}
