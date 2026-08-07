package logging

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/settings"
)

// configuredExporterTypes returns the new multi-exporter list when provided,
// otherwise it falls back to the legacy single logger type.
func configuredExporterTypes(cfg *config.YAMLConfigurationLogger) []string {
	return config.LoggerTypes(cfg)
}

// CreateExporters builds the composite exporter used by osctrl-tls.
func CreateExporters(cfg config.ServiceParameters, mgr *settings.Settings) (*MultiExporter, error) {
	exporterTypes := configuredExporterTypes(cfg.Logger)
	exporters := make([]DataExporter, 0, len(exporterTypes)+1)
	primaryDBConfigured := false

	for _, exporterType := range exporterTypes {
		exporter, usesPrimaryDB, err := CreateExporter(exporterType, cfg, mgr)
		if err != nil {
			return nil, err
		}
		if exporter != nil {
			exporters = append(exporters, exporter)
		}
		if exporterType == config.LoggingDB && usesPrimaryDB {
			primaryDBConfigured = true
		}
	}

	if cfg.Logger != nil && cfg.Logger.AlwaysLog && !primaryDBConfigured {
		if cfg.DB == nil {
			return nil, fmt.Errorf("missing primary DB configuration for always-log exporter")
		}
		dbExporter, err := CreateLoggerDBConfig(cfg.DB)
		if err != nil {
			return nil, err
		}
		dbExporter.Settings(mgr)
		exporters = append(exporters, dbExporter)
	}

	return NewMultiExporter(exporters...), nil
}

// CreateExporter builds one exporter implementation from its configured type.
// This is the only place that should switch on exporter type; request-time
// dispatch goes through the DataExporter interface.
func CreateExporter(exporterType string, cfg config.ServiceParameters, mgr *settings.Settings) (DataExporter, bool, error) {
	if cfg.Logger == nil {
		return nil, false, fmt.Errorf("missing logger configuration")
	}
	switch exporterType {
	case config.LoggingSplunk:
		s, err := CreateLoggerSplunk(cfg.Logger.Splunk)
		if err != nil {
			return nil, false, err
		}
		s.Settings(mgr)
		return s, false, nil
	case config.LoggingGraylog:
		g, err := CreateLoggerGraylog(cfg.Logger.Graylog)
		if err != nil {
			return nil, false, err
		}
		g.Settings(mgr)
		return g, false, nil
	case config.LoggingDB:
		dbConfig := cfg.Logger.DB
		usesPrimaryDB := false
		if cfg.Logger.LoggerDBSame || sameConfigDBPtr(cfg.Logger.DB, cfg.DB) {
			dbConfig = cfg.DB
			usesPrimaryDB = true
		}
		if dbConfig == nil {
			return nil, false, fmt.Errorf("missing DB logger configuration")
		}
		d, err := CreateLoggerDBConfig(dbConfig)
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, usesPrimaryDB, nil
	case config.LoggingStdout:
		d, err := CreateLoggerStdout()
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingFile:
		d, err := CreateLoggerFile(cfg.Logger.Local)
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingNone:
		d, err := CreateLoggerNone()
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingKinesis:
		d, err := CreateLoggerKinesis(cfg.Logger.Kinesis)
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingS3:
		d, err := CreateLoggerS3(cfg.Logger.S3)
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingLogstash:
		d, err := CreateLoggerLogstash(cfg.Logger.Logstash)
		if err != nil {
			return nil, false, err
		}
		d.Settings(mgr)
		return d, false, nil
	case config.LoggingKafka:
		k, err := CreateLoggerKafka(cfg.Logger.Kafka)
		if err != nil {
			return nil, false, err
		}
		k.Settings(mgr)
		return k, false, nil
	case config.LoggingElastic:
		e, err := CreateLoggerElastic(cfg.Logger.Elastic)
		if err != nil {
			return nil, false, err
		}
		e.Settings(mgr)
		return e, false, nil
	default:
		return nil, false, fmt.Errorf("unknown exporter type: %s", exporterType)
	}
}

func sameConfigDBPtr(loggerOne, loggerTwo *config.YAMLConfigurationDB) bool {
	if loggerOne == nil || loggerTwo == nil {
		return false
	}
	return sameConfigDB(*loggerOne, *loggerTwo)
}
