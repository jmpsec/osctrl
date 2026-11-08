package environments

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
	"gorm.io/gorm"
)

// SensitivePath is a file path prefix that only full carve tier may carve or
// read back in an environment.
type SensitivePath struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	EnvironmentID uint           `gorm:"uniqueIndex:idx_env_sensitive_path" json:"environment_id"`
	Path          string         `gorm:"uniqueIndex:idx_env_sensitive_path;size:512" json:"path"`
	CreatedBy     string         `json:"created_by"`
}

// MaxSensitivePathLen is the longest normalized path, in bytes, that can be
// stored: size:512 keeps the unique key under InnoDB's 3072-byte limit at utf8mb4.
const MaxSensitivePathLen = 512

// TableName keeps the table name stable and explicit.
func (SensitivePath) TableName() string { return "env_sensitive_paths" }

// ErrPathNotAbsolute, ErrPathRejected and ErrPathTooLong are caller errors (400).
var (
	ErrPathNotAbsolute = errors.New("path must be absolute")
	ErrPathRejected    = errors.New("path must be absolute and free of device, stream or short-name syntax")
	ErrPathTooLong     = errors.New("path too long")
)

var driveRoot = regexp.MustCompile(`^[a-z]:/`)

// NormalizePath returns the canonical form used to store and match sensitive
// paths: NFC, trimmed, forward slashes, lower-case, cleaned, rooted at "/" or
// at a drive letter ("c:/..."). Trailing dots and spaces on each segment are
// dropped (Windows ignores them). UNC/device prefixes, NTFS streams (":"),
// 8.3 short names ("~") and NUL are rejected rather than interpreted.
//
// The check is lexical only: symlinks and hard links are not resolved, so a
// link to a sensitive file under another name is not caught. PathTouches
// folds the macOS /private and /System/Volumes/Data aliases; other
// firmlinks and NTFS junctions remain uncovered.
func NormalizePath(p string) (string, error) {
	p = strings.ToLower(strings.ToUpper(norm.NFC.String(strings.TrimSpace(p)))) // upper-then-lower folds like NTFS
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "//") || strings.ContainsAny(p, "~\x00") {
		return "", ErrPathRejected
	}
	// ".." and dot/space-only segments ("...", ". .") are rejected before any
	// trimming: Windows may resolve them as parents, so they cannot be Cleaned safely.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || (seg != "" && seg != "." && strings.Trim(seg, ". ") == "") {
			return "", ErrPathRejected
		}
	}
	prefix := ""
	if driveRoot.MatchString(p) {
		// path.Clean would treat "c:" as a plain element, so clean the rest alone.
		prefix, p = p[:2], p[2:]
	} else if !strings.HasPrefix(p, "/") {
		return "", ErrPathNotAbsolute
	}
	if strings.Contains(p, ":") {
		return "", ErrPathRejected
	}
	// Safe to trim now: no ".." can follow.
	return prefix + path.Clean("/"+trimSegments(path.Clean(p))), nil
}

// trimSegments drops trailing dots and spaces from each segment (Windows
// ignores them) and empty segments.
func trimSegments(p string) string {
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if s = strings.TrimRight(s, ". "); s != "" {
			segs = append(segs, s)
		}
	}
	return strings.Join(segs, "/")
}

// PathTouches reports whether path equals, lies under, or is a parent of any
// prefix. Both sides are normalized; an unnormalizable path fails closed
// (true), and so does an unnormalizable stored prefix. /dev and /proc expose
// every file (block devices, /proc/*/root), so they touch any non-empty list.
func PathTouches(p string, prefixes []string) bool {
	np, err := NormalizePath(p)
	if err != nil {
		return true
	}
	if len(prefixes) > 0 && (np == "/dev" || np == "/proc" || strings.HasPrefix(np, "/dev/") || strings.HasPrefix(np, "/proc/")) {
		return true
	}
	// macOS aliases: /private/etc is /etc, /System/Volumes/Data/Users is /Users.
	for _, alias := range []string{"/private/", "/system/volumes/data/"} {
		if rest, ok := strings.CutPrefix(np, alias); ok && pathTouches("/"+rest, prefixes) {
			return true
		}
		// The alias root, or a parent of it, contains the whole aliased tree.
		if len(prefixes) > 0 && strings.HasPrefix(alias, np+"/") {
			return true
		}
	}
	return pathTouches(np, prefixes)
}

// pathTouches is PathTouches for an already-normalized path.
func pathTouches(np string, prefixes []string) bool {
	// A root ("/" or "c:/") trims to "" or "c:" so it prefixes its whole volume.
	np = strings.TrimSuffix(np, "/")
	for _, pre := range prefixes {
		npre, err := NormalizePath(pre)
		if err != nil {
			return true
		}
		npre = strings.TrimSuffix(npre, "/")
		if related(np, npre) {
			return true
		}
		// A driveless path (e.g. `\windows\...`) may mean any drive.
		npDrive, preDrive := driveRoot.MatchString(np+"/"), driveRoot.MatchString(npre+"/")
		if (!npDrive && preDrive && related(np, npre[2:])) || (npDrive && !preDrive && related(np[2:], npre)) {
			return true
		}
	}
	return false
}

func related(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// SensitivePaths lists the sensitive paths of an environment.
func (environment *EnvManager) SensitivePaths(envID uint) ([]SensitivePath, error) {
	var rows []SensitivePath
	if err := environment.DB.Where("environment_id = ?", envID).Order("path").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// AddSensitivePath stores the normalized path, returning the existing row if
// the environment already has it.
func (environment *EnvManager) AddSensitivePath(envID uint, p, createdBy string) (SensitivePath, error) {
	norm, err := NormalizePath(p)
	if err != nil {
		return SensitivePath{}, err
	}
	if len(norm) > MaxSensitivePathLen {
		return SensitivePath{}, ErrPathTooLong
	}
	var row SensitivePath
	err = environment.DB.Where("environment_id = ? AND path = ?", envID, norm).First(&row).Error
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return SensitivePath{}, err
	}
	row = SensitivePath{EnvironmentID: envID, Path: norm, CreatedBy: createdBy}
	if err := environment.DB.Create(&row).Error; err != nil {
		return SensitivePath{}, err
	}
	return row, nil
}

// SensitivePath returns one sensitive path, scoped to its environment.
func (environment *EnvManager) SensitivePath(envID, id uint) (SensitivePath, error) {
	var row SensitivePath
	err := environment.DB.Where("environment_id = ? AND id = ?", envID, id).First(&row).Error
	return row, err
}

// DeleteSensitivePath hard-deletes a path, scoped to its environment.
func (environment *EnvManager) DeleteSensitivePath(envID, id uint) error {
	res := environment.DB.Unscoped().Where("environment_id = ? AND id = ?", envID, id).Delete(&SensitivePath{})
	if res.Error != nil {
		return fmt.Errorf("delete sensitive path: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("sensitive path %d: %w", id, gorm.ErrRecordNotFound)
	}
	return nil
}
