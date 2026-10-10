package vulns

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	osvSourcePrefix = "osv:"
	sourceKEV       = "kev"
	maxRecordBytes  = 8 << 20
	// maxIncremental is where fetching records one by one stops paying off
	// and the archive is downloaded instead.
	maxIncremental = 5000
	storeBatch     = 200
)

// SyncResult reports what one sync processed.
type SyncResult struct{ Written, Skipped int }

// OSVSource syncs ecosystems from an OSV bucket (or a mirror of its layout):
// <base>/<dir>/all.zip, <base>/<dir>/modified_id.csv, <base>/<dir>/<id>.json.
type OSVSource struct {
	db      *gorm.DB
	baseURL string
	fetch   fetcher
	now     func() time.Time
}

func (s *OSVSource) dirURL(dir string) string {
	return strings.TrimRight(s.baseURL, "/") + "/" + url.PathEscape(dir)
}

// Sync brings one ecosystem directory up to date. On error the cursor does
// not move and nothing already stored is removed, so the next run retries.
func (s *OSVSource) Sync(ctx context.Context, dir string) (SyncResult, error) {
	source := osvSourcePrefix + dir
	var state SyncState
	if err := s.db.Where("source = ?", source).Limit(1).Find(&state).Error; err != nil {
		return SyncResult{}, err
	}
	var (
		res    SyncResult
		cursor time.Time
		err    error
	)
	if state.LastSuccess == nil {
		res, cursor, err = s.importArchive(ctx, dir)
	} else {
		var ids []string
		ids, cursor, err = s.modifiedSince(ctx, dir, state.Cursor)
		if err == nil {
			if len(ids) > maxIncremental {
				res, cursor, err = s.importArchive(ctx, dir)
			} else {
				res, err = s.importRecords(ctx, dir, ids)
			}
		}
	}
	if err != nil {
		recordFailure(s.db, source, err, s.now())
		return res, err
	}
	if cursor.Before(state.Cursor) {
		cursor = state.Cursor
	}
	return res, recordSuccess(s.db, source, cursor, res, s.now())
}

// modifiedSince lists ids modified after since. The CSV is newest first, so
// reading stops at the first line at or before the cursor.
func (s *OSVSource) modifiedSince(ctx context.Context, dir string, since time.Time) ([]string, time.Time, error) {
	rc, err := s.fetch.open(ctx, s.dirURL(dir)+"/modified_id.csv")
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rc.Close()
	var (
		ids    []string
		newest time.Time
	)
	sc := bufio.NewScanner(rc)
	for sc.Scan() {
		ts, id, ok := strings.Cut(strings.TrimSpace(sc.Text()), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !t.After(since) {
			break
		}
		if newest.IsZero() {
			newest = t
		}
		ids = append(ids, id)
		if len(ids) > maxIncremental {
			break // the caller falls back to the archive
		}
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return ids, newest, nil
}

func (s *OSVSource) importRecords(ctx context.Context, dir string, ids []string) (SyncResult, error) {
	var res SyncResult
	batch := make([]parsedAdvisory, 0, storeBatch)
	for _, id := range ids {
		raw, err := s.fetch.readAll(ctx, s.dirURL(dir)+"/"+url.PathEscape(id)+".json")
		var se statusError
		if errors.As(err, &se) && se.code == http.StatusNotFound {
			res.Skipped++ // listed, then removed before we fetched it
			continue
		}
		if err != nil {
			return res, err
		}
		p, err := parseOSV(raw)
		if err != nil {
			res.Skipped++
			continue
		}
		batch = append(batch, p)
		res.Written++
		if len(batch) == storeBatch {
			if err := s.store(batch); err != nil {
				return res, err
			}
			batch = batch[:0]
		}
	}
	return res, s.store(batch)
}

// importArchive loads <dir>/all.zip. Entries are parsed in memory and never
// extracted, so an entry's name ("../x") never becomes a filesystem path.
func (s *OSVSource) importArchive(ctx context.Context, dir string) (SyncResult, time.Time, error) {
	tmp, size, err := s.fetch.toTemp(ctx, s.dirURL(dir)+"/all.zip")
	if err != nil {
		return SyncResult{}, time.Time{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	zr, err := zip.NewReader(tmp, size)
	// ErrInsecurePath ("../x" entry names) comes with a usable reader, and
	// is harmless here because nothing is ever extracted.
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return SyncResult{}, time.Time{}, fmt.Errorf("open %s archive: %w", dir, err)
	}
	var (
		res    SyncResult
		newest time.Time
	)
	batch := make([]parsedAdvisory, 0, storeBatch)
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return res, time.Time{}, err
		}
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		raw, err := readEntry(f)
		if err != nil {
			res.Skipped++
			continue
		}
		p, err := parseOSV(raw)
		if err != nil {
			res.Skipped++
			continue
		}
		if p.Advisory.Modified.After(newest) {
			newest = p.Advisory.Modified
		}
		batch = append(batch, p)
		res.Written++
		if len(batch) == storeBatch {
			if err := s.store(batch); err != nil {
				return res, time.Time{}, err
			}
			batch = batch[:0]
		}
	}
	return res, newest, s.store(batch)
}

func readEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRecordBytes {
		return nil, ErrTooLarge
	}
	return raw, nil
}

func (s *OSVSource) store(batch []parsedAdvisory) error {
	if len(batch) == 0 {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, p := range batch {
			if err := storeAdvisory(tx, p); err != nil {
				return err
			}
		}
		return nil
	})
}

// storeAdvisory replaces everything one record contributed. A withdrawn
// record, or one with nothing osctrl matches, leaves no advisory behind.
func storeAdvisory(tx *gorm.DB, p parsedAdvisory) error {
	id := p.Advisory.ID
	if err := tx.Where("advisory_id = ?", id).Delete(&Affected{}).Error; err != nil {
		return err
	}
	if err := tx.Where("advisory_id = ?", id).Delete(&Alias{}).Error; err != nil {
		return err
	}
	if p.Withdrawn || len(p.Affected) == 0 {
		return tx.Where("id = ?", id).Delete(&Advisory{}).Error
	}
	if err := tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		// kev belongs to the KEV sync, so a record update never clears it.
		DoUpdates: clause.AssignmentColumns([]string{"summary", "details", "cvss_vector", "cvss_score", "severity", "ref_urls", "published", "modified"}),
	}).Create(&p.Advisory).Error; err != nil {
		return err
	}
	if len(p.Aliases) > 0 {
		if err := tx.Create(&p.Aliases).Error; err != nil {
			return err
		}
	}
	return tx.CreateInBatches(p.Affected, 500).Error
}

func recordSuccess(db *gorm.DB, source string, cursor time.Time, res SyncResult, now time.Time) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "source"}},
		DoUpdates: clause.AssignmentColumns([]string{"cursor", "last_success", "last_written", "last_skipped"}),
	}).Create(&SyncState{Source: source, Cursor: cursor, LastSuccess: &now, LastWritten: res.Written, LastSkipped: res.Skipped}).Error
}

// recordFailure keeps the error for the feeds page. It is best effort: the
// sync already failed, and a second error here changes nothing.
func recordFailure(db *gorm.DB, source string, cause error, now time.Time) {
	_ = db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "source"}},
		DoUpdates: clause.AssignmentColumns([]string{"last_error", "last_error_at"}),
	}).Create(&SyncState{Source: source, LastError: clipTo(cause.Error(), 2048), LastErrorAt: &now}).Error
}
