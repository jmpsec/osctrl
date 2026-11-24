package console

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// PruneInactiveBefore deletes closed console sessions last updated before
// cutoff, together with their command rows. Active sessions are never deleted
// and must be closed first.
func (m *Manager) PruneInactiveBefore(cutoff time.Time) (int64, error) {
	if m == nil || m.DB == nil {
		return 0, fmt.Errorf("console retention: manager is not initialized")
	}
	var sessions []Session
	if err := m.DB.Unscoped().
		Where("active = ? AND updated_at < ?", false, cutoff).
		Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("list inactive console sessions: %w", err)
	}
	if len(sessions) == 0 {
		return 0, nil
	}
	ids := make([]uint, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}
	if err := m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("session_id IN ?", ids).Delete(&Command{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Where("id IN ?", ids).Delete(&Session{}).Error
	}); err != nil {
		return 0, fmt.Errorf("delete inactive console sessions: %w", err)
	}
	return int64(len(ids)), nil
}
