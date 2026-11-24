package carves

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
)

// PruneCompletedBefore deletes completed carves updated before cutoff,
// including their blocks and any stored S3 objects. In-progress, scheduled, and
// queried carves are never touched. A storage failure skips the database
// deletion for that carve so the next run can retry instead of orphaning
// objects.
func (c *Carves) PruneCompletedBefore(cutoff time.Time) (int64, error) {
	if c == nil || c.DB == nil {
		return 0, fmt.Errorf("carve retention: manager is not initialized")
	}
	var carves []CarvedFile
	if err := c.DB.Unscoped().
		Where("status = ? AND updated_at < ?", StatusCompleted, cutoff).
		Find(&carves).Error; err != nil {
		return 0, fmt.Errorf("list completed carves: %w", err)
	}

	var deleted int64
	var errs []error
	for _, carve := range carves {
		blocks, err := c.GetBlocks(carve.SessionID)
		if err != nil {
			errs = append(errs, fmt.Errorf("carve %s blocks: %w", carve.SessionID, err))
			continue
		}
		if err := c.deleteStoredObjects(carve, blocks); err != nil {
			errs = append(errs, fmt.Errorf("carve %s storage: %w", carve.SessionID, err))
			continue
		}
		if err := c.deleteCarveRows(carve); err != nil {
			errs = append(errs, fmt.Errorf("carve %s rows: %w", carve.SessionID, err))
			continue
		}
		deleted++
	}
	return deleted, errors.Join(errs...)
}

func (c *Carves) deleteStoredObjects(carve CarvedFile, blocks []CarvedBlock) error {
	carver := carve.Carver
	if carver == "" {
		carver = c.Carver
	}
	if carver != config.CarverS3 {
		if carver == config.CarverDB && carve.Archived && carve.ArchivePath != "" {
			if err := os.Remove(carve.ArchivePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("delete carve archive %s - %w", carve.ArchivePath, err)
			}
		}
		return nil
	}
	if c.S3 == nil {
		return fmt.Errorf("s3 carver is not initialized")
	}
	for _, block := range blocks {
		if block.Data == "" {
			continue
		}
		if err := c.S3.DeleteKey(S3URLtoKey(block.Data, c.S3.S3Config.Bucket)); err != nil {
			return err
		}
	}
	if carve.Archived && carve.ArchivePath != "" {
		if err := c.S3.DeleteKey(S3URLtoKey(carve.ArchivePath, c.S3.S3Config.Bucket)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Carves) deleteCarveRows(carve CarvedFile) error {
	return c.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("session_id = ?", carve.SessionID).Delete(&CarvedBlock{}).Error; err != nil {
			return err
		}
		return tx.Unscoped().Delete(&carve).Error
	})
}
