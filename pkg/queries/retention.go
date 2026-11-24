package queries

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PruneCompletedBefore deletes completed, expired, or deleted distributed
// queries updated before cutoff, together with their node-query rows and
// targets. Active queries are never touched, even if they are marked completed
// or expired incorrectly.
func (q *Queries) PruneCompletedBefore(cutoff time.Time) (int64, error) {
	if q == nil || q.DB == nil {
		return 0, fmt.Errorf("query retention: manager is not initialized")
	}
	var old []DistributedQuery
	if err := q.DB.Unscoped().
		Where("active = ?", false).
		Where("(completed = ? OR expired = ? OR deleted = ?)", true, true, true).
		Where("updated_at < ?", cutoff).
		Find(&old).Error; err != nil {
		return 0, fmt.Errorf("list completed queries: %w", err)
	}

	var deleted int64
	var errs []error
	for _, query := range old {
		if err := q.deleteQueryRows(query); err != nil {
			errs = append(errs, fmt.Errorf("query %s: %w", query.Name, err))
			continue
		}
		deleted++
	}
	return deleted, errors.Join(errs...)
}

func (q *Queries) deleteQueryRows(query DistributedQuery) error {
	return q.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("query_id = ?", query.ID).Delete(&NodeQuery{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("name = ?", query.Name).Delete(&DistributedQueryTarget{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Delete(&query).Error
	})
}
