package backend

import (
	"fmt"
	"time"

	"github.com/spf13/viper"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	// DBString to format connection string to database for postgres
	DBString = "host=%s port=%s dbname=%s user=%s password=%s sslmode=%s"
	// DBKey to identify the configuration JSON key
	DBKey = "db"
)

// DBManager have access to backend
type DBManager struct {
	Conn   *gorm.DB
	Config *JSONConfigurationDB
	DSN    string
}

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
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
	return fmt.Sprintf(
		DBString, config.Host, config.Port, config.Name, config.Username, config.Password, config.SSLMode)
}

// GetDB to get PostgreSQL DB using GORM
func (db *DBManager) GetDB() (*gorm.DB, error) {
	dbConn, err := gorm.Open(postgres.Open(db.DSN), &gorm.Config{})
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
		return nil, fmt.Errorf("Failed to load DB configuration - %v", err)
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
		return nil, fmt.Errorf("Failed to get DB - %v", err)
	}
	db.Conn = dbConn
	return db, nil
}
