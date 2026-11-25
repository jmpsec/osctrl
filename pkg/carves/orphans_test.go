package carves

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/jmpsec/osctrl/pkg/config"
)

func TestFindOrphansRejectsNonS3Carver(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateFileCarves(db, config.CarverDB, nil)

	_, err = m.FindOrphans(context.Background(), "prod", time.Time{})
	require.ErrorIs(t, err, ErrOrphanScanUnsupported)
}

func TestReferencedS3KeysIncludesBlocksAndArchives(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	m := CreateFileCarves(db, config.CarverS3, &CarverS3{S3Config: config.S3Carver{Bucket: "bucket"}})

	require.NoError(t, db.Create(&CarvedBlock{
		Environment: "prod", Carver: config.CarverS3, Data: "s3://bucket/env:uuid:session:0",
	}).Error)
	require.NoError(t, db.Create(&CarvedFile{
		Environment: "prod", Archived: true, ArchivePath: "s3://bucket/env:uuid:session:path.tar.gz",
	}).Error)

	keys, err := m.referencedS3Keys("prod")
	require.NoError(t, err)
	require.Contains(t, keys, "env:uuid:session:0")
	require.Contains(t, keys, "env:uuid:session:path.tar.gz")
}

func TestClassifyOrphansHonoursReferencesAndGrace(t *testing.T) {
	now := time.Now()
	objects := []S3Object{
		{Key: "b-referenced", Size: 1, LastModified: now.Add(-2 * time.Hour)},
		{Key: "a-old", Size: 2, LastModified: now.Add(-2 * time.Hour)},
		{Key: "c-new", Size: 3, LastModified: now},
	}
	referenced := map[string]struct{}{"b-referenced": {}}

	count, orphans := classifyOrphans(objects, referenced, now.Add(-time.Hour))
	require.Equal(t, 1, count)
	require.Len(t, orphans, 1)
	require.Equal(t, "a-old", orphans[0].Key)

	// Zero grace reports the new object too, still sorted.
	_, orphans = classifyOrphans(objects, referenced, time.Time{})
	require.Len(t, orphans, 2)
	require.Equal(t, []string{"a-old", "c-new"}, []string{orphans[0].Key, orphans[1].Key})
}
