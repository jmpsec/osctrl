package main

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tracing"
	"github.com/rs/zerolog/log"
)

// logRetentionInterval is the database-log retention cadence. The tables grow
// with every agent check-in, so a daily sweep keeps steady-state load low
// while still bounding storage; the first sweep runs shortly after boot so a
// long-stopped service catches up immediately.
const logRetentionInterval = 24 * time.Hour

// watchLogRetention prunes database-stored osquery status, result and
// on-demand query rows for every environment. Retention is resolved per
// environment (environment override, then global, then the default), and only
// runs against the database exporters actually in use, including a dedicated
// logging database and per-environment sinks.
func watchLogRetention(stop <-chan struct{}, loggerTLS *logging.LoggerTLS, settingsMgr *settings.Settings, envs *environments.EnvManager) {
	pruneLogRetentionOnce(loggerTLS, settingsMgr, envs)
	ticker := time.NewTicker(logRetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			pruneLogRetentionOnce(loggerTLS, settingsMgr, envs)
		}
	}
}

// pruneLogRetentionOnce is the testable body of the retention worker. It
// returns the total rows deleted across every environment and database so a
// caller (or a test) can assert the sweep ran without parsing logs.
func pruneLogRetentionOnce(loggerTLS *logging.LoggerTLS, settingsMgr *settings.Settings, envs *environments.EnvManager) logging.PruneStats {
	_, span := tracing.StartSpan(context.Background(), "retention.logs")
	defer span.End()

	var total logging.PruneStats
	if loggerTLS == nil || settingsMgr == nil || envs == nil {
		return total
	}
	loggers := loggerTLS.DBLoggers()
	if len(loggers) == 0 {
		log.Debug().Msg("log retention: no database log exporters configured; skipping")
		return total
	}
	allEnvs, err := envs.All()
	if err != nil {
		log.Err(err).Msg("log retention: could not list environments")
		return total
	}
	now := time.Now()
	for _, env := range allEnvs {
		retentionDays := settingsMgr.LogRetentionDays(env.ID)
		if retentionDays <= 0 {
			// Zero means keep database logs forever for this environment.
			continue
		}
		cutoff := now.AddDate(0, 0, -int(retentionDays))
		var envStats logging.PruneStats
		for _, dbLogger := range loggers {
			stats, err := dbLogger.PruneEnvironment(env.Name, cutoff)
			envStats.StatusLogs += stats.StatusLogs
			envStats.ResultLogs += stats.ResultLogs
			envStats.QueryLogs += stats.QueryLogs
			if err != nil {
				log.Err(err).
					Str("environment", env.Name).
					Int64("retention_days", retentionDays).
					Msg("log retention: prune failed")
			}
		}
		total.StatusLogs += envStats.StatusLogs
		total.ResultLogs += envStats.ResultLogs
		total.QueryLogs += envStats.QueryLogs
		if envStats.StatusLogs+envStats.ResultLogs+envStats.QueryLogs > 0 {
			log.Info().
				Str("environment", env.Name).
				Int64("retention_days", retentionDays).
				Int64("status_logs", envStats.StatusLogs).
				Int64("result_logs", envStats.ResultLogs).
				Int64("query_logs", envStats.QueryLogs).
				Msg("Pruned database logs")
		}
	}
	return total
}
