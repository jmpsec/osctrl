package queries

import (
	"github.com/jmpsec/osctrl/pkg/events"
	"gorm.io/gorm"
)

// CancelNodeQueries hard-deletes the given node-queries (pending assignments
// a node can no longer receive) and keeps their queries consistent: Expected
// drops by the number cancelled, a standard query with nothing left pending
// completes, and a carve completes once nothing at all is left to arrive.
// Without this a cancelled last target leaves its query active forever.
func (q *Queries) CancelNodeQueries(ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	var changed []DistributedQuery
	err := q.DB.Transaction(func(tx *gorm.DB) error {
		var rows []NodeQuery
		if err := tx.Where("id IN ?", ids).Find(&rows).Error; err != nil {
			return err
		}
		cancelled := make(map[uint]int)
		for _, r := range rows {
			cancelled[r.QueryID]++
		}
		if err := tx.Unscoped().Where("id IN ?", ids).Delete(&NodeQuery{}).Error; err != nil {
			return err
		}
		for queryID, n := range cancelled {
			if err := tx.Model(&DistributedQuery{}).Where("id = ?", queryID).
				Update("expected", gorm.Expr("CASE WHEN expected > ? THEN expected - ? ELSE 0 END", n, n)).Error; err != nil {
				return err
			}
			var query DistributedQuery
			if err := tx.First(&query, queryID).Error; err != nil {
				return err
			}
			var stillPending []uint
			if err := tx.Model(&NodeQuery{}).Where("query_id = ? AND status = ?", queryID, DistributedQueryStatusPending).
				Limit(1).Pluck("id", &stillPending).Error; err != nil {
				return err
			}
			done := len(stillPending) == 0 && (query.Type != CarveQueryType || query.Expected == 0)
			if done && query.Active {
				if err := tx.Model(&query).Updates(map[string]interface{}{"completed": true, "active": false}).Error; err != nil {
					return err
				}
			}
			changed = append(changed, query)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, query := range changed {
		q.notifyChange(query, events.ChangeMetadata)
	}
	return nil
}
