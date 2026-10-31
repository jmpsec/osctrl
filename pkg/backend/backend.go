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
	PostgresDBString = "host=%s port=%d dbname=%s user=%s password=%s sslmode=%s"
	// MySQLDBString to format connection string for MySQL
	MySQLDBString = "%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local"
	// DBKey to identify the configuration JSON key
	DBKey = "db"
	// Database types
	DBTypePostgres = "postgres"
	DBTypeMySQL    = "mysql"
	DBTypeSQLite   = "sqlite"
)

// DBManager have access to backend
type DBManager struct {
	Conn *gorm.DB
	// Read is the read-replica connection when db.read.enabled is set, and
	// the same *gorm.DB as Conn otherwise. Only staleness-tolerant reads that
	// are explicitly routed to it should use it.
	Read   *gorm.DB
	Config *config.YAMLConfigurationDB
	DSN    string
}

// ReadReplicaConfig derives the replica connection settings from the primary:
// fields left empty in db.read inherit the primary's value. Type, database
// name and connection lifetime always follow the primary.
func ReadReplicaConfig(primary config.YAMLConfigurationDB) (config.YAMLConfigurationDB, error) {
	if primary.Type == DBTypeSQLite {
		return config.YAMLConfigurationDB{}, fmt.Errorf("a read replica is not supported with sqlite")
	}
	r := primary
	r.Read = config.YAMLConfigurationDBRead{}
	rd := primary.Read
	if rd.Host != "" {
		r.Host = rd.Host
	}
	if rd.Port != 0 {
		r.Port = rd.Port
	}
	if rd.Username != "" {
		r.Username = rd.Username
	}
	if rd.Password != "" {
		r.Password = rd.Password
	}
	if rd.SSLMode != "" {
		r.SSLMode = rd.SSLMode
	}
	if rd.MaxIdleConns != 0 {
		r.MaxIdleConns = rd.MaxIdleConns
	}
	if rd.MaxOpenConns != 0 {
		r.MaxOpenConns = rd.MaxOpenConns
	}
	return r, nil
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
	return openDB(*db.Config, db.DSN)
}

// openDB opens and pings one connection pool for cfg.
func openDB(cfg config.YAMLConfigurationDB, dsn string) (*gorm.DB, error) {
	var dbConn *gorm.DB
	var err error

	// TranslateError lets handlers use errors.Is(err, gorm.ErrDuplicatedKey)
	// across drivers instead of string-matching the underlying SQLSTATE
	// or driver error text. Required by the env-name uniqueness path in
	// cmd/api/handlers/environments* and by pkg/queries/saved.go.
	gormConfig := &gorm.Config{TranslateError: true}

	// Select the appropriate driver based on database type
	switch cfg.Type {
	case DBTypePostgres:
		dbConn, err = gorm.Open(postgres.Open(dsn), gormConfig)
	case DBTypeMySQL:
		dbConn, err = gorm.Open(mysql.Open(dsn), gormConfig)
	case DBTypeSQLite:
		dbConn, err = gorm.Open(sqlite.Open(dsn), gormConfig)
	default:
		// Default to postgres if type not specified
		dbConn, err = gorm.Open(postgres.Open(dsn), gormConfig)
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
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Second * time.Duration(cfg.ConnMaxLifetime))
	return dbConn, nil
}

// Check to verify if connection is open and ready
// Check to verify if connection is open and ready. With a read replica
// configured, both pools must answer.
func (db *DBManager) Check() error {
	if err := ping(db.Conn); err != nil {
		return err
	}
	if db.Read != nil && db.Read != db.Conn {
		if err := ping(db.Read); err != nil {
			return fmt.Errorf("read replica: %w", err)
		}
	}
	return nil
}

func closeDB(conn *gorm.DB) {
	if sqlDB, err := conn.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

func ping(conn *gorm.DB) error {
	sqlDB, err := conn.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
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
	db.Read = dbConn
	if dbConfig.Read.Enabled {
		readCfg, err := ReadReplicaConfig(*dbConfig)
		if err != nil {
			closeDB(dbConn)
			return nil, err
		}
		readConn, err := openDB(readCfg, PrepareDSN(readCfg))
		if err != nil {
			// The caller may retry; don't leak the primary pool on each attempt.
			closeDB(dbConn)
			return nil, fmt.Errorf("failed to get read replica DB - %w", err)
		}
		db.Read = readConn
	}
	return db, nil
}
