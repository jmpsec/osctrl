package main

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/changes"
	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/httpmetrics"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tracing"
)

// dataRetentionInterval is the cadence for non-log retention. These tables
// grow with completed operations and closed sessions, not with every agent
// check-in, so a daily sweep is sufficient.
const dataRetentionInterval = 24 * time.Hour

// dataRetentionStats reports one sweep's work. It is returned by the testable
// body so tests do not need to parse logs.
type dataRetentionStats struct {
	SantaEvents      int64
	SantaRequests    int64
	SantaChanges     int64
	Carves           int64
	Queries          int64
	ConsoleSessions  int64
	ExplorerSessions int64
}

// watchDataRetention prunes completed carves, Santa events, completed query
// metadata, and inactive console/file-explorer sessions. Each class has its own
// setting and each manager is optional, so a feature that is disabled simply
// contributes nothing.
func watchDataRetention(stop <-chan struct{}, settingsMgr *settings.Settings, santaMgr *santa.Manager, changesMgr *changes.Manager, queriesMgr *queries.Queries, carvesMgr *carves.Carves, consoleMgr *console.Manager, explorerMgr *fileexplorer.Manager) {
	prune := func() {
		pruneDataRetentionOnce(settingsMgr, santaMgr, changesMgr, queriesMgr, carvesMgr, consoleMgr, explorerMgr)
	}
	prune()
	ticker := time.NewTicker(dataRetentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			prune()
		}
	}
}

func pruneDataRetentionOnce(settingsMgr *settings.Settings, santaMgr *santa.Manager, changesMgr *changes.Manager, queriesMgr *queries.Queries, carvesMgr *carves.Carves, consoleMgr *console.Manager, explorerMgr *fileexplorer.Manager) dataRetentionStats {
	_, span := tracing.StartSpan(context.Background(), "retention.api")
	defer span.End()

	var stats dataRetentionStats
	if settingsMgr == nil {
		return stats
	}
	now := time.Now()

	if santaMgr != nil {
		// Expiry-based rows are always safe to prune; they are already dead.
		if _, err := santaMgr.PruneVotes(now); err != nil {
			log.Err(err).Msg("error expiring santa votes")
		}
		if _, err := santaMgr.PruneLinks(now); err != nil {
			log.Err(err).Msg("error pruning santa approval links")
		}
		if _, err := santaMgr.PruneVerdicts(now); err != nil {
			log.Err(err).Msg("error pruning santa risk verdicts")
		}

		days := settingsMgr.SantaEventRetentionDays()
		if days > 0 {
			cutoff := now.AddDate(0, 0, -int(days))
			if n, err := santaMgr.PruneEvents(cutoff); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error pruning santa events")
			} else {
				stats.SantaEvents = n
			}
			if n, err := santaMgr.ExpireRequests(cutoff); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error expiring santa requests")
			} else {
				stats.SantaRequests = n
			}
			if changesMgr != nil {
				if n, err := changesMgr.Prune(cutoff); err != nil {
					log.Err(err).Int64("retention_days", days).Msg("error pruning held changes")
				} else {
					stats.SantaChanges = n
				}
			}
		}
	}

	if carvesMgr != nil {
		days := settingsMgr.CarveRetentionDays()
		if days > 0 {
			if n, err := carvesMgr.PruneCompletedBefore(now.AddDate(0, 0, -int(days))); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error pruning completed carves")
			} else {
				stats.Carves = n
			}
		}
	}

	if queriesMgr != nil {
		days := settingsMgr.QueryMetadataRetentionDays()
		if days > 0 {
			if n, err := queriesMgr.PruneCompletedBefore(now.AddDate(0, 0, -int(days))); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error pruning completed queries")
			} else {
				stats.Queries = n
			}
		}
	}

	if consoleMgr != nil {
		days := settingsMgr.SessionRetentionDays()
		if days > 0 {
			if n, err := consoleMgr.PruneInactiveBefore(now.AddDate(0, 0, -int(days))); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error pruning console sessions")
			} else {
				stats.ConsoleSessions = n
			}
		}
	}

	if explorerMgr != nil {
		days := settingsMgr.SessionRetentionDays()
		if days > 0 {
			if n, err := explorerMgr.PruneInactiveBefore(now.AddDate(0, 0, -int(days))); err != nil {
				log.Err(err).Int64("retention_days", days).Msg("error pruning file explorer sessions")
			} else {
				stats.ExplorerSessions = n
			}
		}
	}

	httpmetrics.RecordRetentionPruned("santa_events", stats.SantaEvents)
	httpmetrics.RecordRetentionPruned("santa_requests", stats.SantaRequests)
	httpmetrics.RecordRetentionPruned("santa_changes", stats.SantaChanges)
	httpmetrics.RecordRetentionPruned("carves", stats.Carves)
	httpmetrics.RecordRetentionPruned("queries", stats.Queries)
	httpmetrics.RecordRetentionPruned("console_sessions", stats.ConsoleSessions)
	httpmetrics.RecordRetentionPruned("file_explorer_sessions", stats.ExplorerSessions)

	if stats.SantaEvents+stats.SantaRequests+stats.SantaChanges+stats.Carves+stats.Queries+stats.ConsoleSessions+stats.ExplorerSessions > 0 {
		log.Info().
			Int64("santa_events", stats.SantaEvents).
			Int64("santa_requests", stats.SantaRequests).
			Int64("santa_changes", stats.SantaChanges).
			Int64("carves", stats.Carves).
			Int64("queries", stats.Queries).
			Int64("console_sessions", stats.ConsoleSessions).
			Int64("explorer_sessions", stats.ExplorerSessions).
			Msg("Pruned retained data")
	}
	return stats
}
