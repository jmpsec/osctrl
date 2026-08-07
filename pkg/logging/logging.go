package logging

import (
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// LoggerTLS will be used to handle logging for the TLS endpoint
type LoggerTLS struct {
	Logging   string
	Exporters DataExporter
	Nodes     *nodes.NodeManager
	Queries   *queries.Queries
}

// CreateLoggerTLS to instantiate a new logger for the TLS endpoint
func CreateLoggerTLS(cfg config.ServiceParameters, mgr *settings.Settings, nodes *nodes.NodeManager, queries *queries.Queries) (*LoggerTLS, error) {
	exporters, err := CreateExporters(cfg, mgr)
	if err != nil {
		return nil, err
	}
	l := &LoggerTLS{
		Logging:   exporters.Name(),
		Exporters: exporters,
		Nodes:     nodes,
		Queries:   queries,
	}
	return l, nil
}

// Log will send status/result logs via the configured method of logging
func (logTLS *LoggerTLS) Log(logType string, data []byte, environment, uuid string, debug bool) {
	if logTLS == nil || logTLS.Exporters == nil {
		log.Warn().Str("type", logType).Msg("no osquery data exporters configured")
		return
	}
	if err := logTLS.Exporters.Export(logType, data, ExportParams{
		Environment: environment,
		UUID:        uuid,
		Debug:       debug,
	}); err != nil {
		log.Err(err).Str("type", logType).Msg("one or more osquery data exporters failed")
	}
}

// QueryLog will send query result logs via the configured method of logging
func (logTLS *LoggerTLS) QueryLog(logType string, data []byte, environment, uuid, name string, status int, debug bool) {
	if logTLS == nil || logTLS.Exporters == nil {
		log.Warn().Str("type", logType).Str("query", name).Msg("no osquery data exporters configured")
		return
	}
	if err := logTLS.Exporters.Export(logType, data, ExportParams{
		Environment: environment,
		UUID:        uuid,
		QueryName:   name,
		Status:      status,
		Debug:       debug,
	}); err != nil {
		log.Err(err).Str("type", logType).Str("query", name).Msg("one or more osquery data exporters failed")
	}
}
