package carves

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
)

// ErrOrphanScanUnsupported is returned when the configured carver has no
// independently listable object storage. Only the S3 carver supports an
// orphan scan; DB blocks and local archives are already addressed through the
// carve metadata itself.
var ErrOrphanScanUnsupported = errors.New("carve orphan scan requires the s3 carver")

// S3Object is one object returned by an S3 listing.
type S3Object struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

// OrphanObject is an S3 object that no carved_files or carved_blocks row
// references.
type OrphanObject struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}

// OrphanReport is the result of one environment-scoped orphan scan.
type OrphanReport struct {
	Environment string         `json:"environment"`
	Scanned     int            `json:"scanned"`
	Referenced  int            `json:"referenced"`
	Orphans     []OrphanObject `json:"orphans"`
}

// FindOrphans lists S3 objects for environment and reports those whose keys are
// not referenced by any carve metadata row. Objects newer than olderThan are
// ignored so an in-flight upload is not reported; pass a zero time to disable
// that grace period. The scan is read-only.
func (c *Carves) FindOrphans(ctx context.Context, environment string, olderThan time.Time) (OrphanReport, error) {
	report := OrphanReport{Environment: environment, Orphans: []OrphanObject{}}
	if c == nil || c.DB == nil {
		return report, fmt.Errorf("carve orphan scan: manager is not initialized")
	}
	if environment == "" {
		return report, fmt.Errorf("carve orphan scan: environment is required")
	}
	if c.Carver != config.CarverS3 || c.S3 == nil {
		return report, ErrOrphanScanUnsupported
	}

	objects, err := c.S3.ListObjects(ctx, environment+":")
	if err != nil {
		return report, fmt.Errorf("list s3 carve objects: %w", err)
	}
	referenced, err := c.referencedS3Keys(environment)
	if err != nil {
		return report, err
	}

	report.Scanned = len(objects)
	report.Referenced, report.Orphans = classifyOrphans(objects, referenced, olderThan)
	return report, nil
}

func classifyOrphans(objects []S3Object, referenced map[string]struct{}, olderThan time.Time) (int, []OrphanObject) {
	referencedCount := 0
	orphans := make([]OrphanObject, 0)
	for _, object := range objects {
		if _, ok := referenced[object.Key]; ok {
			referencedCount++
			continue
		}
		if !olderThan.IsZero() && !object.LastModified.Before(olderThan) {
			continue
		}
		orphans = append(orphans, OrphanObject(object))
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Key < orphans[j].Key })
	return referencedCount, orphans
}

// referencedS3Keys loads the S3 keys still claimed by block rows and archived
// carve rows. Unscoped is deliberate: a soft-deleted carve is still metadata,
// so its objects are not reported as orphans until the row is hard-deleted.
func (c *Carves) referencedS3Keys(environment string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})

	var blockData []string
	if err := c.DB.Unscoped().Model(&CarvedBlock{}).
		Where("environment = ? AND carver = ?", environment, config.CarverS3).
		Pluck("data", &blockData).Error; err != nil {
		return nil, fmt.Errorf("load referenced carve blocks: %w", err)
	}
	for _, data := range blockData {
		if data != "" {
			keys[S3URLtoKey(data, c.S3.S3Config.Bucket)] = struct{}{}
		}
	}

	var archivePaths []string
	if err := c.DB.Unscoped().Model(&CarvedFile{}).
		Where("environment = ? AND archive_path <> ''", environment).
		Pluck("archive_path", &archivePaths).Error; err != nil {
		return nil, fmt.Errorf("load referenced carve archives: %w", err)
	}
	for _, archivePath := range archivePaths {
		keys[S3URLtoKey(archivePath, c.S3.S3Config.Bucket)] = struct{}{}
	}
	return keys, nil
}
