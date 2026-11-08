package environments

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/etc//shadow", "/etc/shadow"},
		{"/etc/./shadow/", "/etc/shadow"},
		{"/ETC/Shadow", "/etc/shadow"},
		{`C:\Windows\System32\config\SAM`, "c:/windows/system32/config/sam"},
		{"  /tmp/x  ", "/tmp/x"},
		{"/", "/"},
		{"C:\\", "c:/"},
		{"/etc/shadow.", "/etc/shadow"},
		{"/etc/shadow. ", "/etc/shadow"},
		{"/etc./shadow", "/etc/shadow"},
		{"c:/windows/sam. .", "c:/windows/sam"},
		{"/Cafe\u0301", "/caf\u00e9"},
	}
	for _, tt := range tests {
		got, err := NormalizePath(tt.in)
		assert.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got, tt.in)
	}
	for _, in := range []string{"/etc/../etc/shadow", "/..", "c:/../..", "/etc/.../shadow", "c:/windows/system32/zz/.. /config/sam", "/etc/shadow/../x", "/a/.../b", "/a/. ./b", "/a/ /b",
		"etc/shadow", "", "c:", "c:relative", "  ", "./etc",
		`\\?\C:\Windows\System32\config\SAM`, `\\.\C:\x`, `\\localhost\c$\x`, "//etc/shadow",
		"c:/windows/sam::$DATA", "/etc/a:b", "c:/progra~1/x", "/etc/shadow\x00"} {
		_, err := NormalizePath(in)
		assert.Error(t, err, in)
		assert.True(t, errors.Is(err, ErrPathNotAbsolute) || errors.Is(err, ErrPathRejected), in)
	}
}

func TestPathTouches(t *testing.T) {
	prefixes := []string{"/etc/shadow", "c:/windows/system32/config"}
	for _, p := range []string{"/etc/shadow", "/etc//shadow", "/ETC/SHADOW", "/etc", "/",
		`C:\Windows\System32\config\SAM`, "c:/windows", "c:/", "relative", "/etc/shadow/x"} {
		assert.True(t, PathTouches(p, prefixes), p)
	}
	for _, p := range []string{`\Windows\System32\config\SAM`,
		`\\?\C:\Windows\System32\config\SAM`, `\\.\C:\Windows\System32\config\SAM`,
		`\\localhost\c$\windows\system32\config\sam`, "c:/windows/system32/config/sam::$DATA",
		"c:/windows/system32/config::$index_allocation/sam", "c:/windows/system32/config/sam.",
		"c:/windows/system32/config./sam", "/etc/shadow\x00", "/dev/sda", "/dev", "/proc/self/root/etc/passwd"} {
		assert.True(t, PathTouches(p, prefixes), p)
	}
	for _, p := range []string{"c:/windows/system32/config/sam", "d:/windows/system32/config/sam"} {
		assert.True(t, PathTouches(p, []string{`\Windows\System32\config`}), p)
	}
	assert.True(t, PathTouches("c:/etc", []string{"/etc/shadow"}))
	for _, p := range []string{"/home/alice/secret/.../../y", "/home/alice/secret/.. /y", "/home/alice/secret/. ./../y",
		"c:/windows/system32/config/.../../sam", "c:/windows/system32/config/.. ./../sam",
		"/etc/../dev/sda", "c:/windows/system32/zz/.. /config/sam"} {
		assert.True(t, PathTouches(p, []string{"/home/alice/secret", "c:/windows/system32/config"}), p)
	}
	assert.False(t, PathTouches("/procfoo", prefixes))
	assert.False(t, PathTouches("/etc/./passwd", prefixes))
	assert.True(t, PathTouches("c:/w\u0131ndows/system32/config/sam", []string{"c:/windows/system32/config"}))
	assert.True(t, PathTouches("c:/progra~1/secret", []string{"c:/program files/secret"}))
	assert.False(t, PathTouches("/dev/sda", nil))
	assert.False(t, PathTouches("/devices/x", prefixes))
	for _, p := range []string{"/etc/shadow-backup", "/etc/passwd", "/var/log/syslog", "d:/windows/system32/config"} {
		assert.False(t, PathTouches(p, prefixes), p)
	}
	assert.False(t, PathTouches("/etc/passwd", nil))
	assert.True(t, PathTouches("/etc/passwd", []string{"/"}))
	assert.True(t, PathTouches("/etc/passwd", []string{"bogus", "/etc"}))
	assert.True(t, PathTouches("/etc/passwd", []string{"bogus"}))
}

func TestSensitivePathsCRUD(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	assert.NoError(t, m.DB.AutoMigrate(&SensitivePath{}))
	a, err := m.AddSensitivePath(1, "/ETC//shadow", "admin")
	assert.NoError(t, err)
	b, err := m.AddSensitivePath(1, "/etc/shadow", "other")
	assert.NoError(t, err)
	assert.Equal(t, a.ID, b.ID)
	_, err = m.AddSensitivePath(1, "etc", "admin")
	assert.Error(t, err)
	rows, err := m.SensitivePaths(1)
	assert.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, "/etc/shadow", rows[0].Path)
	assert.Equal(t, "admin", rows[0].CreatedBy)
	other, err := m.SensitivePaths(2)
	assert.NoError(t, err)
	assert.Empty(t, other)
	assert.True(t, errors.Is(m.DeleteSensitivePath(2, a.ID), gorm.ErrRecordNotFound))
	assert.NoError(t, m.DeleteSensitivePath(1, a.ID))
	rows, _ = m.SensitivePaths(1)
	assert.Empty(t, rows)
}

func TestDeleteEnvRemovesSensitivePaths(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	assert.NoError(t, m.DB.AutoMigrate(&SensitivePath{}))
	nodeTables(t, m)
	env := newEnv(t, m, "e1", "uuid-1")
	_, err := m.AddSensitivePath(env.ID, "/etc/shadow", "admin")
	assert.NoError(t, err)
	_, err = m.AddSensitivePath(env.ID+100, "/etc/shadow", "admin")
	assert.NoError(t, err)
	assert.NoError(t, m.Delete("e1"))
	var n int64
	assert.NoError(t, m.DB.Unscoped().Model(&SensitivePath{}).Where("environment_id = ?", env.ID).Count(&n).Error)
	assert.Zero(t, n)
	assert.NoError(t, m.DB.Unscoped().Model(&SensitivePath{}).Count(&n).Error)
	assert.EqualValues(t, 1, n)
}

func TestAddSensitivePathTooLong(t *testing.T) {
	m := &EnvManager{DB: setupTestDB(t)}
	assert.NoError(t, m.DB.AutoMigrate(&SensitivePath{}))
	_, err := m.AddSensitivePath(1, "/"+strings.Repeat("a", 512), "admin")
	assert.ErrorIs(t, err, ErrPathTooLong)
	_, err = m.AddSensitivePath(1, "/"+strings.Repeat("a", 511), "admin")
	assert.NoError(t, err)
}

func TestPathTouchesMacAliases(t *testing.T) {
	assert.True(t, PathTouches("/private/etc/shadow", []string{"/etc/shadow"}))
	assert.True(t, PathTouches("/private/etc", []string{"/etc/shadow"}))
	assert.True(t, PathTouches("/System/Volumes/Data/Users/x/secret", []string{"/users/x"}))
	assert.True(t, PathTouches("/system/volumes/data/users", []string{"/users/x"}))
	assert.False(t, PathTouches("/private/var/log", []string{"/etc/shadow"}))
	assert.False(t, PathTouches("/privateetc/shadow", []string{"/etc/shadow"}))
	// An alias root, or a parent of one, contains the whole aliased tree.
	for _, p := range []string{"/private", "/PRIVATE/", "/System/Volumes/Data", "/system/volumes", "/System"} {
		assert.True(t, PathTouches(p, []string{"/etc/shadow"}), p)
	}
	assert.False(t, PathTouches("/system/library", []string{"/etc/shadow"}))
	assert.False(t, PathTouches("/private", nil))
}

func TestSensitivePathJSON(t *testing.T) {
	b, err := json.Marshal(SensitivePath{ID: 3, Path: "/etc"})
	assert.NoError(t, err)
	var m map[string]any
	assert.NoError(t, json.Unmarshal(b, &m))
	for _, k := range []string{"id", "created_at", "updated_at", "environment_id", "path", "created_by"} {
		assert.Contains(t, m, k)
	}
	assert.Len(t, m, 6)
}
