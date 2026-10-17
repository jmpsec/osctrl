package extensions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"gorm.io/gorm"
)

const (
	// MaxFileSize is the largest extension binary accepted.
	MaxFileSize = 64 << 20
	// ChunkSize is the size of each stored chunk (the last one may be shorter).
	ChunkSize = 1 << 20
)

// platforms is the allowed set of platform and arch pairs.
var platforms = map[string]map[string]bool{
	"darwin":  {"amd64": true, "arm64": true, "universal": true},
	"linux":   {"amd64": true, "arm64": true},
	"windows": {"amd64": true},
}

// ValidPlatform reports whether platform and arch are in the allowed set.
func ValidPlatform(platform, arch string) bool { return platforms[platform][arch] }

// PutFile stores the extension binary for platform and arch from r, replacing
// any previous one. The content is hashed and written chunk by chunk inside a
// transaction, so an oversize or failed upload stores nothing.
func (m *Manager) PutFile(ctx context.Context, extID uint, platform, arch, filename string, r io.Reader, by string) (*ExtensionFile, error) {
	if !ValidPlatform(platform, arch) {
		return nil, fmt.Errorf("%w: platform %q arch %q", ErrInvalid, platform, arch)
	}
	var tmpKey [16]byte
	if _, err := rand.Read(tmpKey[:]); err != nil {
		return nil, err
	}
	// Chunks are written under a temporary key until the content SHA is known.
	tmp := "tmp-" + hex.EncodeToString(tmpKey[:])
	var f ExtensionFile
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&Extension{}, extID).Error; err != nil {
			return notFound(err)
		}
		h := sha256.New()
		buf := make([]byte, ChunkSize)
		lr := io.LimitReader(strictEOF{r}, MaxFileSize+1)
		var size int64
		for seq := 0; ; seq++ {
			n, err := io.ReadFull(lr, buf)
			if n > 0 {
				size += int64(n)
				if size > MaxFileSize {
					return ErrTooLarge
				}
				h.Write(buf[:n])
				if err := tx.Create(&ExtensionChunk{SHA256: tmp, Seq: seq, Data: buf[:n]}).Error; err != nil {
					return err
				}
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			if err != nil {
				return err
			}
		}
		if size == 0 {
			return ErrEmpty
		}
		sha := hex.EncodeToString(h.Sum(nil))
		var existing int64
		if err := tx.Model(&ExtensionChunk{}).Where("sha256 = ?", sha).Count(&existing).Error; err != nil {
			return err
		}
		// ponytail: two concurrent first uploads of the same bytes can both
		// keep their chunks; StreamFile skips the duplicate seqs. Add a unique
		// (sha256, seq) index if that ever matters.
		var err error
		if existing > 0 {
			err = tx.Where("sha256 = ?", tmp).Delete(&ExtensionChunk{}).Error
		} else {
			err = tx.Model(&ExtensionChunk{}).Where("sha256 = ?", tmp).Update("sha256", sha).Error
		}
		if err != nil {
			return err
		}

		err = tx.Where("extension_id = ? AND platform = ? AND arch = ?", extID, platform, arch).First(&f).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		oldSHA := f.SHA256
		f.ExtensionID, f.Platform, f.Arch = extID, platform, arch
		f.Size, f.SHA256, f.Filename, f.UpdatedBy = size, sha, filename, by
		if err := tx.Save(&f).Error; err != nil {
			return err
		}
		if oldSHA != "" && oldSHA != sha {
			return dropUnreferenced(tx, oldSHA)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// strictEOF reports a reader's own io.ErrUnexpectedEOF (a truncated
// multipart body) as ErrTruncated, so PutFile can tell it apart from the
// io.ErrUnexpectedEOF io.ReadFull returns for a short last chunk.
type strictEOF struct{ r io.Reader }

func (s strictEOF) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		err = ErrTruncated
	}
	return n, err
}

// DeleteFile removes the binary for platform and arch and its chunks unless
// another file uses them.
func (m *Manager) DeleteFile(extID uint, platform, arch string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var f ExtensionFile
		if err := tx.Where("extension_id = ? AND platform = ? AND arch = ?", extID, platform, arch).First(&f).Error; err != nil {
			return notFound(err)
		}
		if err := tx.Unscoped().Delete(&f).Error; err != nil {
			return err
		}
		return dropUnreferenced(tx, f.SHA256)
	})
}

// dropUnreferenced deletes the chunks of sha when no file uses them.
func dropUnreferenced(tx *gorm.DB, sha string) error {
	var n int64
	if err := tx.Model(&ExtensionFile{}).Where("sha256 = ?", sha).Count(&n).Error; err != nil || n > 0 {
		return err
	}
	return tx.Where("sha256 = ?", sha).Delete(&ExtensionChunk{}).Error
}

// StreamFile writes the content with this SHA-256 to w one chunk at a time,
// so at most one chunk is in memory and no connection is held while writing.
func (m *Manager) StreamFile(ctx context.Context, sha string, w io.Writer) (int64, error) {
	db := m.db.WithContext(ctx)
	var refs []ExtensionChunk
	if err := db.Select("id, seq").Where("sha256 = ?", sha).Order("seq, id").Find(&refs).Error; err != nil {
		return 0, err
	}
	if len(refs) == 0 {
		return 0, ErrNotFound
	}
	var written int64
	for i, ref := range refs {
		if i > 0 && ref.Seq == refs[i-1].Seq {
			continue
		}
		var c ExtensionChunk
		if err := db.Select("data").First(&c, ref.ID).Error; err != nil {
			return written, fmt.Errorf("reading chunk %d of %s: %w", ref.Seq, sha, err)
		}
		n, err := w.Write(c.Data)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// FileSize returns the size of the content with this SHA-256.
func (m *Manager) FileSize(sha string) (int64, error) {
	var f ExtensionFile
	if err := m.db.Select("size").Where("sha256 = ?", sha).First(&f).Error; err != nil {
		return 0, notFound(err)
	}
	return f.Size, nil
}
