package backend

import (
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/jinzhu/gorm"
	// Import postgres dialect
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	// DBString to format connection string to database
	DBString = "host=%s port=%s dbname=%s user=%s password=%s sslmode=disable"
	// DBDialect for the database to use
	DBDialect = "postgres"
	// DBKey to identify the configuration JSON key
	DBKey = "db"
)

// JSONConfigurationDB to hold all backend configuration values
type JSONConfigurationDB struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	MaxOpenConns    int    `json:"max_open_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
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
	if err := dbRaw.Unmarshal(&config); err != nil {
		return config, err
	}
	// No errors!
	return config, nil
}

// GetDB to get PostgreSQL DB using GORM
func GetDB(config JSONConfigurationDB) (*gorm.DB, error) {
	// Generate DB connection string
	postgresDSN := fmt.Sprintf(
		DBString, config.Host, config.Port, config.Name, config.Username, config.Password)
	// Connect to DB
	db, err := gorm.Open(DBDialect, postgresDSN)
	if err != nil {
		return nil, err
	}
	// Performance settings for DB access
	db.DB().SetMaxIdleConns(config.MaxIdleConns)
	db.DB().SetMaxOpenConns(config.MaxOpenConns)
	db.DB().SetConnMaxLifetime(time.Second * time.Duration(config.ConnMaxLifetime))

	return db, nil
}
