package logging

import (
	"sync"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

// LoggerTLS will be used to handle logging for the TLS endpoint.
//
// It is environment-aware: ExportersFor(envID) returns the MultiExporter
// for that environment, falling back to the global (key 0) set when the
// environment has no sinks of its own. The exporter map is swapped
// atomically by ReplaceExporters during a hot reload so an in-flight
// request finishes against its already-resolved exporter pointer while
// new requests pick up the new sinks.
type LoggerTLS struct {
	mu        sync.RWMutex
	exporters map[uint]*MultiExporter // key 0 = global fallback
	// Logging is kept for backwards-compatible diagnostics (the
	// comma-joined name list of the global set). Callers that previously
	// read l.Logging should migrate to ExportersFor(0).Name().
	Logging string
	Nodes   *nodes.NodeManager
	Queries *queries.Queries
}

// CreateLoggerTLS to instantiate a new logger for the TLS endpoint from
// YAML configuration. Retained for backwards compatibility and tests.
// New code should prefer CreateLoggerTLSWith.
func CreateLoggerTLS(cfg config.ServiceParameters, mgr *settings.Settings, nodes *nodes.NodeManager, queries *queries.Queries) (*LoggerTLS, error) {
	exporters, err := CreateExporters(cfg, mgr)
	if err != nil {
		return nil, err
	}
	return CreateLoggerTLSWith(map[uint]*MultiExporter{0: exporters}, nodes, queries), nil
}

// CreateLoggerTLSWith constructs an env-aware LoggerTLS from a
// pre-built map of per-environment exporters. Key 0 is the global
// fallback. The map is used as-is (not copied); callers must not
// mutate it after handing it over.
func CreateLoggerTLSWith(exporters map[uint]*MultiExporter, nodes *nodes.NodeManager, queries *queries.Queries) *LoggerTLS {
	l := &LoggerTLS{
		exporters: exporters,
		Nodes:     nodes,
		Queries:   queries,
	}
	if g, ok := exporters[0]; ok {
		l.Logging = g.Name()
	}
	return l
}

// ExportersFor returns the MultiExporter for the given environment,
// falling back to the global (key 0) set when the environment has no
// exporters of its own. Returns nil when neither exists — callers
// must handle nil (Log/QueryLog do so by warning and dropping).
func (logTLS *LoggerTLS) ExportersFor(envID uint) *MultiExporter {
	if logTLS == nil {
		return nil
	}
	logTLS.mu.RLock()
	defer logTLS.mu.RUnlock()
	if exp, ok := logTLS.exporters[envID]; ok && exp != nil {
		return exp
	}
	if envID != 0 {
		if exp, ok := logTLS.exporters[0]; ok && exp != nil {
			return exp
		}
	}
	return nil
}

// AllExporters returns a snapshot of the entire exporter map. Used by
// the SinkStatsWriter to iterate every live MultiExporter and snapshot
// its per-sink atomic counters. The returned map is a shallow copy so
// the caller can iterate without holding the read lock.
func (logTLS *LoggerTLS) AllExporters() map[uint]*MultiExporter {
	if logTLS == nil {
		return nil
	}
	logTLS.mu.RLock()
	defer logTLS.mu.RUnlock()
	out := make(map[uint]*MultiExporter, len(logTLS.exporters))
	for k, v := range logTLS.exporters {
		out[k] = v
	}
	return out
}

// ReplaceExporters atomically swaps the entire exporter map and closes
// every exporter in the old map. The swap happens under the write
// lock; any Export call that already resolved its MultiExporter
// pointer finishes against the old set, then the old set is closed.
//
// In-flight logs may be dropped during the switch because the old
// exporters' resources (Kafka producer, DB pool) are closed
// immediately after the swap. Callers that need to drain should do so
// before calling ReplaceExporters.
func (logTLS *LoggerTLS) ReplaceExporters(newExporters map[uint]*MultiExporter) {
	if logTLS == nil {
		return
	}
	logTLS.mu.Lock()
	old := logTLS.exporters
	logTLS.exporters = newExporters
	if g, ok := newExporters[0]; ok && g != nil {
		logTLS.Logging = g.Name()
	} else {
		logTLS.Logging = ""
	}
	logTLS.mu.Unlock()
	for _, exp := range old {
		if exp == nil {
			continue
		}
		if err := exp.Close(); err != nil {
			log.Err(err).Str("exporters", exp.Name()).Msg("error closing old exporter during reload")
		}
	}
}

// Log will send status/result logs via the configured method of logging.
func (logTLS *LoggerTLS) Log(logType string, data []byte, environment, uuid string, debug bool) {
	logTLS.logWithEnv(logType, data, environment, uuid, "", 0, debug, false)
}

// QueryLog will send query result logs via the configured method of logging.
func (logTLS *LoggerTLS) QueryLog(logType string, data []byte, environment, uuid, name string, status int, debug bool) {
	logTLS.logWithEnv(logType, data, environment, uuid, name, status, debug, true)
}

// LogWithEnv is the env-scoped dispatch used by the TLS log handler. It
// resolves the exporter set for the given environment and forwards the
// payload. envID is the numeric environment ID (env.ID); the string
// environment name is carried alongside for exporter metadata.
func (logTLS *LoggerTLS) LogWithEnv(logType string, data []byte, envID uint, environment, uuid string, debug bool) {
	logTLS.logWithEnv(logType, data, environment, uuid, "", 0, debug, false, envID)
}

// QueryLogWithEnv is the env-scoped dispatch for on-demand query
// results. See LogWithEnv for the envID semantics.
func (logTLS *LoggerTLS) QueryLogWithEnv(logType string, data []byte, envID uint, environment, uuid, name string, status int, debug bool) {
	logTLS.logWithEnv(logType, data, environment, uuid, name, status, debug, true, envID)
}

func (logTLS *LoggerTLS) logWithEnv(logType string, data []byte, environment, uuid, name string, status int, debug, isQuery bool, envIDs ...uint) {
	if logTLS == nil {
		log.Warn().Str("type", logType).Msg("no osquery data exporters configured (LoggerTLS is nil)")
		return
	}
	var envID uint
	if len(envIDs) > 0 {
		envID = envIDs[0]
	}
	exporters := logTLS.ExportersFor(envID)
	if exporters == nil {
		log.Warn().Str("type", logType).Uint("env_id", envID).Msg("no osquery data exporters configured for environment")
		return
	}
	params := ExportParams{
		Environment: environment,
		UUID:        uuid,
		QueryName:   name,
		Status:      status,
		Debug:       debug,
	}
	if err := exporters.Export(logType, data, params); err != nil {
		if isQuery {
			log.Err(err).Str("type", logType).Str("query", name).Msg("one or more osquery data exporters failed")
		} else {
			log.Err(err).Str("type", logType).Msg("one or more osquery data exporters failed")
		}
	}
}
