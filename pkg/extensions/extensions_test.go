package extensions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
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

func mkExt(t *testing.T, m *Manager, name string, cmdExec bool) *Extension {
	t.Helper()
	e, err := m.Create(Extension{Name: name, Version: "1.0", CommandExecution: cmdExec, CreatedBy: "admin"})
	require.NoError(t, err)
	return e
}

// payload returns n deterministic, seed-dependent bytes.
func payload(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ seed
	}
	return b
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func putFile(t *testing.T, m *Manager, extID uint, platform, arch string, data []byte) *ExtensionFile {
	t.Helper()
	f, err := m.PutFile(context.Background(), extID, platform, arch, "x.ext", bytes.NewReader(data), "admin")
	require.NoError(t, err)
	return f
}

func chunkCount(t *testing.T, m *Manager, sha string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, m.db.Model(&ExtensionChunk{}).Where("sha256 = ?", sha).Count(&n).Error)
	return n
}

func stream(t *testing.T, m *Manager, sha string) []byte {
	t.Helper()
	var buf bytes.Buffer
	n, err := m.StreamFile(context.Background(), sha, &buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)
	return buf.Bytes()
}

func TestCreateValidatesName(t *testing.T) {
	m := newTestManager(t)
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"osquery_exec", true},
		{"a-B_9", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"", false},
		{"../x", false},
		{"a/b", false},
		{"a.ext", false},
		{"a b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Create(Extension{Name: tc.name})
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrInvalid)
			}
		})
	}
}

func TestCreateDuplicate(t *testing.T) {
	m := newTestManager(t)
	mkExt(t, m, "dup", false)
	_, err := m.Create(Extension{Name: "dup"})
	assert.ErrorIs(t, err, ErrDuplicate)
}

func TestUpdate(t *testing.T) {
	m := newTestManager(t)
	e := mkExt(t, m, "ordinary", false)
	tr := true
	got, err := m.Update(e.ID, "desc", "2.0", &tr, "bob")
	require.NoError(t, err)
	assert.True(t, got.CommandExecution)
	assert.Equal(t, "2.0", got.Version)
	assert.Equal(t, "bob", got.UpdatedBy)

	assert.ErrorIs(t, m.UnassignEnv(1, e.ID), ErrNotFound) // nothing to remove
	_, err = m.AssignNode("node-1", 1, e.ID, nil, "root")
	require.NoError(t, err)
	fl := false
	_, err = m.Update(e.ID, "desc", "2.0", &fl, "bob")
	assert.ErrorIs(t, err, ErrAssigned)
	// Same value is not a change.
	_, err = m.Update(e.ID, "new desc", "2.1", &tr, "bob")
	assert.NoError(t, err)

	_, err = m.Update(999, "", "", nil, "bob")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteRefusedWhileAssigned(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	fa := putFile(t, m, a.ID, "linux", "amd64", payload(100, 1))
	fc := putFile(t, m, c.ID, "linux", "amd64", payload(100, 2))
	require.NoError(t, m.AssignEnv(1, a.ID, "admin"))
	_, err := m.AssignNode("node-1", 1, c.ID, nil, "root")
	require.NoError(t, err)

	assert.ErrorIs(t, m.Delete(a.ID), ErrAssigned)
	assert.ErrorIs(t, m.Delete(c.ID), ErrAssigned)

	require.NoError(t, m.UnassignEnv(1, a.ID))
	require.NoError(t, m.UnassignNode("node-1", c.ID))
	require.NoError(t, m.Delete(a.ID))
	require.NoError(t, m.Delete(c.ID))

	_, err = m.Get(a.ID)
	assert.ErrorIs(t, err, ErrNotFound)
	var files int64
	require.NoError(t, m.db.Unscoped().Model(&ExtensionFile{}).Count(&files).Error)
	assert.Zero(t, files)
	assert.Zero(t, chunkCount(t, m, fa.SHA256))
	assert.Zero(t, chunkCount(t, m, fc.SHA256))
	// The name can be reused after a delete.
	mkExt(t, m, "a", false)
}

func TestList(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	putFile(t, m, a.ID, "linux", "amd64", payload(10, 1))
	putFile(t, m, a.ID, "darwin", "universal", payload(10, 2))
	require.NoError(t, m.AssignEnv(1, a.ID, "admin"))
	require.NoError(t, m.AssignEnv(2, a.ID, "admin"))
	_, err := m.AssignNode("n1", 1, c.ID, nil, "root")
	require.NoError(t, err)

	views, err := m.List()
	require.NoError(t, err)
	require.Len(t, views, 2)
	assert.Equal(t, "a", views[0].Name)
	assert.Len(t, views[0].Files, 2)
	assert.Equal(t, int64(2), views[0].EnvAssignments)
	assert.Equal(t, int64(0), views[0].NodeAssignments)
	assert.Equal(t, "c", views[1].Name)
	assert.Empty(t, views[1].Files)
	assert.Equal(t, int64(1), views[1].NodeAssignments)
}

func TestPutFileChunksAndStream(t *testing.T) {
	m := newTestManager(t)
	e := mkExt(t, m, "a", false)
	data := payload(3*ChunkSize, 1)
	f := putFile(t, m, e.ID, "linux", "amd64", data)
	assert.Equal(t, shaHex(data), f.SHA256)
	assert.Equal(t, int64(len(data)), f.Size)
	assert.Equal(t, "x.ext", f.Filename)
	assert.Equal(t, int64(3), chunkCount(t, m, f.SHA256))
	assert.True(t, bytes.Equal(data, stream(t, m, f.SHA256)))

	_, err := m.StreamFile(context.Background(), strings.Repeat("0", 64), io.Discard)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestPutFileReplace(t *testing.T) {
	m := newTestManager(t)
	e := mkExt(t, m, "a", false)
	other := mkExt(t, m, "b", false)
	old := payload(2*ChunkSize+5, 1)
	f1 := putFile(t, m, e.ID, "linux", "amd64", old)

	f2 := putFile(t, m, e.ID, "linux", "amd64", payload(100, 2))
	assert.NotEqual(t, f1.SHA256, f2.SHA256)
	assert.Equal(t, f1.ID, f2.ID)
	assert.Zero(t, chunkCount(t, m, f1.SHA256))
	var files int64
	require.NoError(t, m.db.Model(&ExtensionFile{}).Count(&files).Error)
	assert.Equal(t, int64(1), files)

	// Old bytes still used by another extension: replacing keeps them.
	putFile(t, m, e.ID, "linux", "amd64", old)
	putFile(t, m, other.ID, "linux", "amd64", old)
	putFile(t, m, e.ID, "linux", "amd64", payload(50, 3))
	assert.Equal(t, int64(3), chunkCount(t, m, f1.SHA256))
	assert.True(t, bytes.Equal(old, stream(t, m, f1.SHA256)))
}

func TestPutFileSharedChunks(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	b := mkExt(t, m, "b", false)
	data := payload(ChunkSize+1, 9)
	fa := putFile(t, m, a.ID, "linux", "amd64", data)
	fb := putFile(t, m, b.ID, "linux", "amd64", data)
	assert.Equal(t, fa.SHA256, fb.SHA256)
	assert.Equal(t, int64(2), chunkCount(t, m, fa.SHA256))

	require.NoError(t, m.Delete(a.ID))
	assert.True(t, bytes.Equal(data, stream(t, m, fb.SHA256)))

	require.NoError(t, m.DeleteFile(b.ID, "linux", "amd64"))
	assert.Zero(t, chunkCount(t, m, fb.SHA256))
	assert.ErrorIs(t, m.DeleteFile(b.ID, "linux", "amd64"), ErrNotFound)
}

func TestPutFileLimits(t *testing.T) {
	m := newTestManager(t)
	e := mkExt(t, m, "a", false)
	ctx := context.Background()

	f, err := m.PutFile(ctx, e.ID, "linux", "amd64", "x", io.LimitReader(zeros{}, MaxFileSize), "admin")
	require.NoError(t, err)
	assert.Equal(t, int64(MaxFileSize), f.Size)
	assert.Equal(t, int64(64), chunkCount(t, m, f.SHA256))

	_, err = m.PutFile(ctx, e.ID, "linux", "arm64", "x", io.LimitReader(zeros{}, MaxFileSize+1), "admin")
	assert.ErrorIs(t, err, ErrTooLarge)

	_, err = m.PutFile(ctx, e.ID, "linux", "arm64", "x", bytes.NewReader(nil), "admin")
	assert.ErrorIs(t, err, ErrEmpty)

	var files, chunks int64
	require.NoError(t, m.db.Model(&ExtensionFile{}).Count(&files).Error)
	require.NoError(t, m.db.Model(&ExtensionChunk{}).Count(&chunks).Error)
	assert.Equal(t, int64(1), files)
	assert.Equal(t, int64(64), chunks)

	for _, pa := range [][2]string{{"linux", "universal"}, {"windows", "arm64"}, {"freebsd", "amd64"}, {"darwin", "x86"}, {"", ""}} {
		_, err = m.PutFile(ctx, e.ID, pa[0], pa[1], "x", bytes.NewReader([]byte("x")), "admin")
		assert.ErrorIs(t, err, ErrInvalid, pa)
	}
	_, err = m.PutFile(ctx, 999, "linux", "amd64", "x", bytes.NewReader([]byte("x")), "admin")
	assert.ErrorIs(t, err, ErrNotFound)
}

// A reader that fails with io.ErrUnexpectedEOF (a truncated multipart body)
// must not be stored as a short file.
func TestPutFileTruncated(t *testing.T) {
	m := newTestManager(t)
	e := mkExt(t, m, "a", false)
	r := io.MultiReader(bytes.NewReader(payload(ChunkSize+10, 1)), iotestErr{io.ErrUnexpectedEOF})
	_, err := m.PutFile(context.Background(), e.ID, "linux", "amd64", "x", r, "admin")
	assert.ErrorIs(t, err, ErrTruncated)
	var files, chunks int64
	require.NoError(t, m.db.Model(&ExtensionFile{}).Count(&files).Error)
	require.NoError(t, m.db.Model(&ExtensionChunk{}).Count(&chunks).Error)
	assert.Zero(t, files)
	assert.Zero(t, chunks)
}

type iotestErr struct{ err error }

func (r iotestErr) Read([]byte) (int, error) { return 0, r.err }

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestAssignments(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)

	assert.ErrorIs(t, m.AssignEnv(1, c.ID, "admin"), ErrCommandExecution)
	_, err := m.AssignNode("n1", 1, a.ID, nil, "root")
	assert.ErrorIs(t, err, ErrNotCommandExecution)
	assert.ErrorIs(t, m.AssignEnv(1, 999, "admin"), ErrNotFound)

	require.NoError(t, m.AssignEnv(1, a.ID, "admin"))
	require.NoError(t, m.AssignEnv(1, a.ID, "admin")) // idempotent
	envExts, err := m.EnvExtensions(1)
	require.NoError(t, err)
	require.Len(t, envExts, 1)
	assert.Equal(t, "a", envExts[0].Name)

	exp1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp2 := exp1.Add(24 * time.Hour)
	n, err := m.AssignNode("n1", 1, c.ID, &exp1, "root")
	require.NoError(t, err)
	assert.True(t, n.ExpiresAt.Equal(exp1))
	n, err = m.AssignNode("n1", 1, c.ID, &exp2, "root")
	require.NoError(t, err)
	assert.True(t, n.ExpiresAt.Equal(exp2))
	list, err := m.NodeAssignments("n1")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.True(t, list[0].ExpiresAt.Equal(exp2))
	n, err = m.AssignNode("n1", 1, c.ID, nil, "root")
	require.NoError(t, err)
	assert.Nil(t, n.ExpiresAt)

	require.NoError(t, m.UnassignNode("n1", c.ID))
	list, err = m.NodeAssignments("n1")
	require.NoError(t, err)
	assert.Empty(t, list)
	// Removing what is not there reports ErrNotFound, so callers do not
	// audit a removal that did not happen.
	assert.ErrorIs(t, m.UnassignNode("n1", c.ID), ErrNotFound)
	assert.ErrorIs(t, m.UnassignNode("n1", a.ID), ErrNotFound)
	require.NoError(t, m.UnassignEnv(1, a.ID))
	assert.ErrorIs(t, m.UnassignEnv(1, a.ID), ErrNotFound)
	assert.ErrorIs(t, m.UnassignEnv(2, a.ID), ErrNotFound)
}

func TestEffectiveSet(t *testing.T) {
	m := newTestManager(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	u := mkExt(t, m, "u", false)
	fa := putFile(t, m, a.ID, "linux", "amd64", payload(10, 1))
	fc := putFile(t, m, c.ID, "linux", "amd64", payload(10, 2))
	fu := putFile(t, m, u.ID, "darwin", "universal", payload(10, 3))
	fua := putFile(t, m, u.ID, "darwin", "amd64", payload(10, 4))
	require.NoError(t, m.AssignEnv(1, a.ID, "admin"))
	require.NoError(t, m.AssignEnv(1, u.ID, "admin"))
	future := now.Add(time.Hour)
	_, err := m.AssignNode("n1", 1, c.ID, &future, "root")
	require.NoError(t, err)

	names := func(es []types.OsctrldExtensionEntry) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Name)
		}
		return out
	}

	got, err := m.EffectiveSet(1, "n1", "linux", "amd64", now)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "c"}, names(got))
	assert.Equal(t, types.OsctrldExtensionEntry{Name: "a", SHA256: fa.SHA256, Size: 10}, got[0])
	assert.Equal(t, fc.SHA256, got[1].SHA256)

	got, err = m.EffectiveSet(1, "n2", "linux", "amd64", now)
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, names(got))

	// Assigned in env 1, so the node in env 2 does not get it.
	got, err = m.EffectiveSet(2, "n1", "linux", "amd64", now)
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = m.EffectiveSet(1, "n1", "linux", "amd64", future)
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, names(got), "expired")

	got, err = m.EffectiveSet(1, "n1", "darwin", "arm64", now)
	require.NoError(t, err)
	require.Equal(t, []string{"u"}, names(got))
	assert.Equal(t, fu.SHA256, got[0].SHA256)

	got, err = m.EffectiveSet(1, "n1", "darwin", "amd64", now)
	require.NoError(t, err)
	require.Equal(t, []string{"u"}, names(got))
	assert.Equal(t, fua.SHA256, got[0].SHA256, "exact arch wins over universal")

	got, err = m.EffectiveSet(1, "n1", "linux", "arm64", now)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestInEnvSet(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	x := mkExt(t, m, "x", false)
	e := mkExt(t, m, "e", true)
	fa := putFile(t, m, a.ID, "linux", "amd64", payload(10, 1))
	fc := putFile(t, m, c.ID, "linux", "amd64", payload(10, 2))
	fx := putFile(t, m, x.ID, "linux", "amd64", payload(10, 3))
	fe := putFile(t, m, e.ID, "linux", "amd64", payload(10, 4))
	require.NoError(t, m.AssignEnv(1, a.ID, "admin"))
	require.NoError(t, m.AssignEnv(2, x.ID, "admin"))
	_, err := m.AssignNode("n1", 1, c.ID, nil, "root")
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	_, err = m.AssignNode("n1", 1, e.ID, &past, "root")
	require.NoError(t, err)

	for _, tc := range []struct {
		sha  string
		want bool
	}{
		{fa.SHA256, true},
		{fc.SHA256, true},
		{fx.SHA256, false},
		{fe.SHA256, false},
		{strings.Repeat("a", 64), false},
	} {
		ok, err := m.InEnvSet(1, tc.sha)
		require.NoError(t, err)
		assert.Equal(t, tc.want, ok, tc.sha)
	}
}

func TestRecordStatus(t *testing.T) {
	m := newTestManager(t)
	mkExt(t, m, "a", false)
	mkExt(t, m, "b", false)
	c := mkExt(t, m, "c", true)
	sha := strings.Repeat("a", 64)
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	reported := at.Add(time.Minute)

	require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
		{Name: "a", SHA256: sha, Result: "ok", At: at},
		{Name: "b", SHA256: sha, Result: "rejected", Error: "x" + strings.Repeat("é", 1000), At: at},
		{Name: "../x", SHA256: sha, Result: "ok"},
		{Name: "a", SHA256: strings.ToUpper(sha), Result: "ok"},
		{Name: "a", SHA256: "abc", Result: "ok"},
		{Name: "a", SHA256: sha, Result: "maybe"},
		{Name: "unknown", SHA256: sha, Result: "ok"},
		{Name: "c", SHA256: sha, Result: "ok", At: time.Date(500, 1, 1, 0, 0, 0, 0, time.UTC)},
	}, reported))
	got, err := m.NodeStatuses("n1")
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "a", got[0].Name)
	assert.Equal(t, "ok", got[0].Result)
	assert.Nil(t, got[2].At, "out-of-range node time dropped")
	assert.True(t, got[0].At.Equal(at))
	assert.True(t, got[0].ReportedAt.Equal(reported))
	assert.Equal(t, uint(1), got[0].EnvironmentID)
	assert.Equal(t, "b", got[1].Name)
	// Cut at 1024 bytes would split a rune; the partial rune is dropped.
	assert.Equal(t, "x"+strings.Repeat("é", 511), got[1].Error)
	assert.True(t, utf8.ValidString(got[1].Error))

	// Upsert by node+name.
	sha2 := strings.Repeat("b", 64)
	require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
		{Name: "a", SHA256: sha2, Result: "rejected", Error: "boom"},
	}, reported.Add(time.Minute)))
	got, err = m.NodeStatuses("n1")
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, sha2, got[0].SHA256)
	assert.Equal(t, "rejected", got[0].Result)
	assert.Equal(t, "boom", got[0].Error)
	assert.Nil(t, got[0].At)

	// DeleteNode removes assignments and statuses.
	_, err = m.AssignNode("n1", 1, c.ID, nil, "root")
	require.NoError(t, err)
	require.NoError(t, m.DeleteNode("n1"))
	got, err = m.NodeStatuses("n1")
	require.NoError(t, err)
	assert.Empty(t, got)
	list, err := m.NodeAssignments("n1")
	require.NoError(t, err)
	assert.Empty(t, list)
	var rows int64
	require.NoError(t, m.db.Unscoped().Model(&NodeExtension{}).Count(&rows).Error)
	assert.Zero(t, rows)
}

// TestChunkColumnTypes guards the chunk data column: MySQL blob is only
// 64 KiB, so a size tag below that would break 1 MiB chunks.
func TestChunkColumnTypes(t *testing.T) {
	s, err := schema.Parse(&ExtensionChunk{}, &sync.Map{}, schema.NamingStrategy{})
	require.NoError(t, err)
	f := s.LookUpField("Data")
	require.NotNil(t, f)
	assert.Equal(t, "longblob", mysql.Dialector{Config: &mysql.Config{}}.DataTypeOf(f))
}

// TestServeTimeSplit: rows that bypass AssignEnv/AssignNode (e.g. a race
// with a CommandExecution flip) must not serve across the split.
func TestServeTimeSplit(t *testing.T) {
	m := newTestManager(t)
	now := time.Now()
	c := mkExt(t, m, "c", true)
	a := mkExt(t, m, "a", false)
	fc := putFile(t, m, c.ID, "linux", "amd64", payload(10, 1))
	fa := putFile(t, m, a.ID, "linux", "amd64", payload(10, 2))
	require.NoError(t, m.db.Create(&EnvExtension{EnvironmentID: 1, ExtensionID: c.ID}).Error)
	require.NoError(t, m.db.Create(&NodeExtension{NodeUUID: "n1", EnvironmentID: 1, ExtensionID: a.ID}).Error)

	got, err := m.EffectiveSet(1, "n1", "linux", "amd64", now)
	require.NoError(t, err)
	assert.Empty(t, got)
	for _, sha := range []string{fc.SHA256, fa.SHA256} {
		ok, err := m.InEnvSet(1, sha)
		require.NoError(t, err)
		assert.False(t, ok, sha)
	}
}

func TestFileSize(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	f := putFile(t, m, a.ID, "linux", "amd64", payload(ChunkSize+5, 1))
	size, err := m.FileSize(f.SHA256)
	require.NoError(t, err)
	assert.Equal(t, int64(ChunkSize+5), size)
	_, err = m.FileSize(strings.Repeat("a", 64))
	assert.ErrorIs(t, err, ErrNotFound)
}

// okStatus reports name as ok for nodeUUID in environment 1.
func okStatus(t *testing.T, m *Manager, nodeUUID string, names ...string) {
	t.Helper()
	var s []types.OsctrldExtensionStatus
	for _, n := range names {
		s = append(s, types.OsctrldExtensionStatus{Name: n, SHA256: shaHex([]byte(n)), Result: "ok", At: time.Now()})
	}
	require.NoError(t, m.RecordStatus(nodeUUID, 1, s, time.Now()))
}

func statusNames(t *testing.T, m *Manager, nodeUUID string) []string {
	t.Helper()
	rows, err := m.NodeStatuses(nodeUUID)
	require.NoError(t, err)
	names := []string{}
	for _, r := range rows {
		names = append(names, r.Name)
	}
	return names
}

// A removed assignment takes its status along, so assigning it again never
// shows a stale ok; a status reported after the removal is kept.
func TestUnassignNodeDropsStatus(t *testing.T) {
	m := newTestManager(t)
	mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	_, err := m.AssignNode("n1", 1, c.ID, nil, "root")
	require.NoError(t, err)
	_, err = m.AssignNode("n2", 1, c.ID, nil, "root")
	require.NoError(t, err)
	okStatus(t, m, "n1", "a", "c")
	okStatus(t, m, "n2", "c")

	require.NoError(t, m.UnassignNode("n1", c.ID))
	assert.Equal(t, []string{"a"}, statusNames(t, m, "n1"))
	assert.Equal(t, []string{"c"}, statusNames(t, m, "n2"), "other nodes keep theirs")

	okStatus(t, m, "n1", "c")
	assert.Equal(t, []string{"a", "c"}, statusNames(t, m, "n1"))
}

// Hosts with case-insensitive file systems would put both names in one file.
func TestCreateDuplicateCaseInsensitive(t *testing.T) {
	m := newTestManager(t)
	mkExt(t, m, "Dup", false)
	for _, name := range []string{"dup", "DUP", "Dup"} {
		_, err := m.Create(Extension{Name: name})
		assert.ErrorIs(t, err, ErrDuplicate, name)
	}
	mkExt(t, m, "dup2", false)
}

func TestDeleteDropsStatus(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	mkExt(t, m, "b", false)
	okStatus(t, m, "n1", "a", "b")
	okStatus(t, m, "n2", "a")

	require.NoError(t, m.Delete(a.ID))
	assert.Equal(t, []string{"b"}, statusNames(t, m, "n1"))
	assert.Empty(t, statusNames(t, m, "n2"))
}

// osctrld reports a failed removal as kept and a successful one as removed
func TestRecordStatusKeptRemoved(t *testing.T) {
	m := newTestManager(t)
	mkExt(t, m, "c", true)
	report := func(result, msg string) {
		require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
			{Name: "c", SHA256: strings.Repeat("a", 64), Result: result, Error: msg},
		}, time.Now()))
	}
	report("kept", "osqueryd was not running")
	got, err := m.NodeStatuses("n1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "kept", got[0].Result)
	assert.Equal(t, "osqueryd was not running", got[0].Error)

	report("removed", "")
	got, err = m.NodeStatuses("n1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "removed", got[0].Result)
	assert.Empty(t, got[0].Error)
}

// A command-execution extension osctrld reports as kept on a host cannot be
// deleted, so the evidence that it is still there is not erased
func TestDeleteRefusedWhileKept(t *testing.T) {
	m := newTestManager(t)
	a := mkExt(t, m, "a", false)
	c := mkExt(t, m, "c", true)
	report := func(name, result string) {
		require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
			{Name: name, SHA256: strings.Repeat("a", 64), Result: result},
		}, time.Now()))
	}
	report("c", "kept")
	report("a", "kept")

	assert.ErrorIs(t, m.Delete(c.ID), ErrKept)
	_, err := m.Get(c.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "c"}, statusNames(t, m, "n1"))
	require.NoError(t, m.Delete(a.ID), "ordinary extensions are not held back")

	report("c", "removed")
	require.NoError(t, m.Delete(c.ID))
	assert.Empty(t, statusNames(t, m, "n1"))
}

// Removing an assignment keeps a kept status: the extension is still there
func TestUnassignNodeKeepsKept(t *testing.T) {
	m := newTestManager(t)
	c := mkExt(t, m, "c", true)
	past := time.Now().Add(-time.Hour)
	_, err := m.AssignNode("n1", 1, c.ID, &past, "root")
	require.NoError(t, err)
	require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
		{Name: "c", SHA256: strings.Repeat("a", 64), Result: ResultKept, Error: "busy"},
	}, time.Now()))

	require.NoError(t, m.UnassignNode("n1", c.ID))
	got, err := m.NodeStatuses("n1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ResultKept, got[0].Result)
	assert.ErrorIs(t, m.Delete(c.ID), ErrKept)
}

// Command execution cannot be switched off while a host reports it kept
func TestUpdateRefusedWhileKept(t *testing.T) {
	m := newTestManager(t)
	c := mkExt(t, m, "c", true)
	report := func(result string) {
		require.NoError(t, m.RecordStatus("n1", 1, []types.OsctrldExtensionStatus{
			{Name: "c", SHA256: strings.Repeat("a", 64), Result: result},
		}, time.Now()))
	}
	off := false
	report(ResultKept)
	_, err := m.Update(c.ID, "d", "1", &off, "root")
	assert.ErrorIs(t, err, ErrKept)
	got, err := m.Get(c.ID)
	require.NoError(t, err)
	assert.True(t, got.CommandExecution)
	_, err = m.Update(c.ID, "d", "1", nil, "root")
	require.NoError(t, err, "other fields can still change")

	report(ResultRemoved)
	got, err = m.Update(c.ID, "d", "1", &off, "root")
	require.NoError(t, err)
	assert.False(t, got.CommandExecution)
}
