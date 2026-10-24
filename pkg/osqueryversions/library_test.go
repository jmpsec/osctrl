package osqueryversions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	digestA = strings.Repeat("a", 64)
	digestB = strings.Repeat("b", 64)
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{TranslateError: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	m, err := NewManager(db)
	require.NoError(t, err)
	return m
}

func TestValidVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"5.12.1": true, "5.12": true, "5.12.1.2": true,
		"5": false, "5.x": false, "5.12.1\n": false, "5.1234567": false, "5.09": true, "1234567.1": false,
	} {
		assert.Equal(t, want, ValidVersion(v), v)
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"5.9.0", "5.12.1", -1},
		{"5.12.1", "5.9.0", 1},
		{"5.12.1", "5.12.1", 0},
		{"5.12", "5.12.0", 0},
		{"5.09", "5.9", 0},
		{"5.12.1.1", "5.12.1", 1},
		{"5.12.1", "5.12.1.1", -1},
	}
	for _, tc := range tests {
		got, err := Compare(tc.a, tc.b)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got, tc.a+" vs "+tc.b)
	}
	_, err := Compare("5.x", "5.12.1")
	assert.Error(t, err)
	_, err = Compare("5.12.1", "bad")
	assert.Error(t, err)
}

func TestValidEntry(t *testing.T) {
	tests := []struct {
		name                         string
		platform, arch, format, hash string
		ok                           bool
	}{
		{"linux deb amd64", "linux", "amd64", "deb", digestA, true},
		{"linux rpm arm64", "linux", "arm64", "rpm", digestA, true},
		{"darwin pkg universal", "darwin", "universal", "pkg", digestA, true},
		{"darwin amd64", "darwin", "amd64", "pkg", digestA, false},
		{"windows msi", "windows", "amd64", "msi", digestA, true},
		{"windows msi arm64", "windows", "arm64", "msi", digestA, false},
		{"windows 386", "windows", "386", "msi", digestA, false},
		{"windows universal", "windows", "universal", "msi", digestA, false},
		{"windows zip", "windows", "amd64", "zip", digestA, false},
		{"linux pkg", "linux", "amd64", "pkg", digestA, false},
		{"short digest", "linux", "amd64", "deb", "abc", false},
		{"uppercase digest", "linux", "amd64", "deb", strings.Repeat("A", 64), false},
		{"non hex digest", "linux", "amd64", "deb", strings.Repeat("g", 64), false},
	}
	for _, tc := range tests {
		err := ValidEntry(tc.platform, tc.arch, tc.format, tc.hash)
		if tc.ok {
			assert.NoError(t, err, tc.name)
		} else {
			assert.Error(t, err, tc.name)
		}
	}
}

func TestPutEntriesUpserts(t *testing.T) {
	m := newTestManager(t)
	e := DigestEntry{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: digestA}
	require.NoError(t, m.PutEntries("5.12.1", []DigestEntry{e}, "admin"))
	e.SHA256 = digestB
	require.NoError(t, m.PutEntries("5.12.1", []DigestEntry{e}, "other"))
	got, err := m.GetEntries("5.12.1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, digestB, got[0].SHA256)
	assert.Equal(t, "other", got[0].CreatedBy)
	assert.Equal(t, "5.12.1", got[0].Version)
}

func TestListVersionsGroupsEntries(t *testing.T) {
	m := newTestManager(t)
	require.NoError(t, m.PutEntries("5.12.1", []DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: digestA},
		{Platform: "darwin", Arch: "universal", Format: "pkg", SHA256: digestA},
	}, "admin"))
	require.NoError(t, m.PutEntries("5.9.0", []DigestEntry{
		{Platform: "linux", Arch: "arm64", Format: "rpm", SHA256: digestB},
	}, "admin"))
	views, err := m.ListVersions()
	require.NoError(t, err)
	require.Len(t, views, 2)
	// Newest first
	assert.Equal(t, "5.12.1", views[0].Version)
	assert.Len(t, views[0].Entries, 2)
	assert.Equal(t, "5.9.0", views[1].Version)
	assert.Len(t, views[1].Entries, 1)
	require.NoError(t, m.DeleteVersion("5.12.1"))
	got, err := m.GetEntries("5.12.1")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPutEntriesRejectsInvalidEntryAndStoresNothing(t *testing.T) {
	m := newTestManager(t)
	err := m.PutEntries("5.12.1", []DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: digestA},
		{Platform: "windows", Arch: "386", Format: "msi", SHA256: digestA},
	}, "admin")
	require.Error(t, err)
	got, err := m.GetEntries("5.12.1")
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Error(t, m.PutEntries("bad", []DigestEntry{{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: digestA}}, "admin"))
	assert.Error(t, m.PutEntries("5.12.1", nil, "admin"))
}

// The Go rule and its SQL fragment must agree for every platform string.
func TestNodePlatformSupportedMatchesSQL(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec("CREATE TABLE n (platform TEXT)").Error)
	for _, p := range []string{"windows", "Windows", "ubuntu", "darwin", "freebsd", "FreeBSD", ""} {
		require.NoError(t, db.Exec("DELETE FROM n").Error)
		require.NoError(t, db.Exec("INSERT INTO n (platform) VALUES (?)", p).Error)
		var c int64
		require.NoError(t, db.Table("n").Where(SupportedNodePlatformSQL("platform")).Count(&c).Error)
		assert.Equal(t, NodePlatformSupported(p), c == 1, p)
	}
	require.NoError(t, db.Exec("DELETE FROM n").Error)
	require.NoError(t, db.Exec("INSERT INTO n (platform) VALUES (NULL)").Error)
	var c int64
	require.NoError(t, db.Table("n").Where(SupportedNodePlatformSQL("platform")).Count(&c).Error)
	assert.Equal(t, NodePlatformSupported(""), c == 1)
}
