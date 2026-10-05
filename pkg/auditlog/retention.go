package auditlog

import (
	"context"
	"time"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
)

const retentionBatchSize = 1000

// PruneBatch physically deletes at most 1000 expired rows, including rows
// already soft-deleted. Each statement is bounded and safe to retry or race
// with another API replica. Callers bound total work with a context deadline.
func (m *AuditLogManager) PruneBatch(ctx context.Context, days int64, now time.Time) (int64, error) {
	if err := settings.ValidateAuditLogRetentionDays(days); err != nil {
		return 0, err
	}
	cutoff := now.UTC().AddDate(0, 0, -int(days))
	db := m.DB.WithContext(ctx).Unscoped()
	var ids []uint
	if err := db.Model(&AuditLog{}).Where("created_at < ?", cutoff).
		Order("created_at ASC").Limit(retentionBatchSize).Pluck("id", &ids).Error; err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}
	result := db.Where("id IN ? AND created_at < ?", ids, cutoff).Delete(&AuditLog{})
	return result.RowsAffected, result.Error
}

// RunRetention runs on the API, pruning audit rows for all services even when
// new audit writes are disabled. The hourly sweep catches up gradually after
// downtime; its five-minute deadline prevents an unbounded cleanup job.
func (m *AuditLogManager) RunRetention(ctx context.Context, retention func() (int64, error)) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		days, err := retention()
		if err == nil {
			var total int64
			sweep, cancel := context.WithTimeout(ctx, 5*time.Minute)
			now := time.Now()
			for sweep.Err() == nil {
				var deleted int64
				deleted, err = m.PruneBatch(sweep, days, now)
				total += deleted
				if err != nil || deleted == 0 {
					break
				}
				// Yield between batches to avoid monopolizing the database.
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-sweep.Done():
					timer.Stop()
				case <-timer.C:
				}
			}
			cancel()
			if total > 0 {
				log.Info().Int64("deleted", total).Msg("pruned audit history")
			}
		}
		if err != nil && ctx.Err() == nil {
			log.Error().Err(err).Msg("audit retention sweep failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
