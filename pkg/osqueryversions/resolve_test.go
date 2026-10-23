package osqueryversions

import (
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Now()

func seed(t *testing.T, m *Manager, version string, entries ...DigestEntry) {
	t.Helper()
	require.NoError(t, m.PutEntries(version, entries, "t"))
}

func deb(sha string) DigestEntry {
	return DigestEntry{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: sha}
}

func linuxIn(installed string) ResolveInput {
	return ResolveInput{EnvironmentID: 1, NodeUUID: "u1", Platform: "linux", Arch: "amd64", Format: "deb", InstalledVersion: installed}
}

// libWithTarget has 5.12.1 and 5.13.0 deb digests and an environment target of 5.13.0.
func libWithTarget(t *testing.T) *Manager {
	m := newTestManager(t)
	seed(t, m, "5.12.1", deb(digestA))
	seed(t, m, "5.13.0", deb(digestB))
	_, err := m.SetEnvTarget(1, "5.13.0", "admin")
	require.NoError(t, err)
	return m
}

func TestResolveEnvironmentTarget(t *testing.T) {
	m := libWithTarget(t)
	r, err := m.Resolve(linuxIn("5.12.1"), now)
	require.NoError(t, err)
	assert.Empty(t, r.Reason)
	assert.Equal(t, "environment", r.Source)
	assert.Equal(t, &Ref{Version: "5.13.0", SHA256: digestB}, r.Target)
	assert.Equal(t, &Ref{Version: "5.12.1", SHA256: digestA}, r.Previous)
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{32}$`), r.RequestID)
}

func TestResolvePinOverridesEnvironment(t *testing.T) {
	m := libWithTarget(t)
	seed(t, m, "5.12.2", deb(digestA))
	exp := now.Add(time.Hour)
	_, err := m.SetPin("u1", 1, "5.12.2", &exp, "admin")
	require.NoError(t, err)
	r, err := m.Resolve(linuxIn("5.12.1"), now)
	require.NoError(t, err)
	assert.Empty(t, r.Reason)
	assert.Equal(t, "pin", r.Source)
	assert.Equal(t, "5.12.2", r.Target.Version)
}

func TestResolveExpiredPinFallsBack(t *testing.T) {
	m := libWithTarget(t)
	seed(t, m, "5.12.2", deb(digestA))
	exp := now.Add(time.Hour)
	_, err := m.SetPin("u1", 1, "5.12.2", &exp, "admin")
	require.NoError(t, err)
	r, err := m.Resolve(linuxIn("5.12.1"), now.Add(2*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, "environment", r.Source)
	assert.Equal(t, "5.13.0", r.Target.Version)
}

func TestResolveNoTarget(t *testing.T) {
	m := newTestManager(t)
	r, err := m.Resolve(linuxIn("5.12.1"), now)
	require.NoError(t, err)
	assert.Equal(t, ReasonNoTarget, r.Reason)
	assert.Empty(t, r.Source)
	assert.Empty(t, r.RequestID)
	assert.Nil(t, r.Target)
}

func TestResolveAheadOfTargetWhenInstalledEqualOrHigher(t *testing.T) {
	m := libWithTarget(t)
	for _, v := range []string{"5.13.0", "5.13", "5.14.0"} {
		r, err := m.Resolve(linuxIn(v), now)
		require.NoError(t, err)
		assert.Equal(t, ReasonAheadOfTarget, r.Reason, v)
		assert.Nil(t, r.Target)
	}
}

func TestResolveNoDigestForTarget(t *testing.T) {
	m := newTestManager(t)
	seed(t, m, "5.12.1", deb(digestA))
	seed(t, m, "5.13.0", DigestEntry{Platform: "linux", Arch: "amd64", Format: "rpm", SHA256: digestB})
	_, err := m.SetEnvTarget(1, "5.13.0", "admin")
	require.NoError(t, err)
	r, err := m.Resolve(linuxIn("5.12.1"), now)
	require.NoError(t, err)
	assert.Equal(t, ReasonNoDigestForTarget, r.Reason)
}

func TestResolveNoDigestForInstalled(t *testing.T) {
	m := libWithTarget(t)
	for _, v := range []string{"5.11.0", "", "garbage"} {
		r, err := m.Resolve(linuxIn(v), now)
		require.NoError(t, err)
		assert.Equal(t, ReasonNoDigestForInstalled, r.Reason, v)
		assert.Nil(t, r.Target)
		assert.Nil(t, r.Previous)
	}
}

func TestResolveWindowsAndUnsupportedCombos(t *testing.T) {
	m := libWithTarget(t)
	for _, c := range [][3]string{{"windows", "amd64", "msi"}, {"linux", "386", "deb"}, {"freebsd", "amd64", "pkg"}} {
		in := linuxIn("5.12.1")
		in.Platform, in.Arch, in.Format = c[0], c[1], c[2]
		r, err := m.Resolve(in, now)
		require.NoError(t, err)
		assert.Equal(t, ReasonUnsupportedPlatform, r.Reason, c)
	}
}

func TestResolveDarwinUsesUniversalDigest(t *testing.T) {
	m := newTestManager(t)
	u := func(s string) DigestEntry {
		return DigestEntry{Platform: "darwin", Arch: "universal", Format: "pkg", SHA256: s}
	}
	seed(t, m, "5.12.1", u(digestA))
	seed(t, m, "5.13.0", u(digestB))
	_, err := m.SetEnvTarget(1, "5.13.0", "admin")
	require.NoError(t, err)
	for _, arch := range []string{"arm64", "amd64"} {
		r, err := m.Resolve(ResolveInput{EnvironmentID: 1, NodeUUID: "u1", Platform: "darwin", Arch: arch, Format: "pkg", InstalledVersion: "5.12.1"}, now)
		require.NoError(t, err)
		assert.Empty(t, r.Reason, arch)
		assert.Equal(t, digestB, r.Target.SHA256)
		assert.Equal(t, digestA, r.Previous.SHA256)
	}
}

func TestSetEnvTargetRequiresLibraryVersion(t *testing.T) {
	m := newTestManager(t)
	_, err := m.SetEnvTarget(1, "5.13.0", "admin")
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = m.SetEnvTarget(1, "bad", "admin")
	assert.ErrorIs(t, err, ErrInvalid)
	got, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSetEnvTargetSameVersionChangesRequestId(t *testing.T) {
	m := libWithTarget(t)
	a, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	b, err := m.SetEnvTarget(1, "5.13.0", "admin")
	require.NoError(t, err)
	assert.NotEqual(t, a.RequestID, b.RequestID)
	got, err := m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.Equal(t, b.RequestID, got.RequestID)
	require.NoError(t, m.ClearEnvTarget(1))
	got, err = m.GetEnvTarget(1)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSetPinRejectsPastExpiry(t *testing.T) {
	m := libWithTarget(t)
	past := time.Now().Add(-time.Minute)
	_, err := m.SetPin("u1", 1, "5.13.0", &past, "admin")
	assert.ErrorIs(t, err, ErrInvalid)
	_, err = m.SetPin("u1", 1, "5.13.0", nil, "admin")
	require.NoError(t, err)
	p, err := m.GetPin("u1")
	require.NoError(t, err)
	assert.False(t, p.Expired(now))
	require.NoError(t, m.DeletePin("u1"))
	p, err = m.GetPin("u1")
	require.NoError(t, err)
	assert.Nil(t, p)
}

func TestDeleteVersionInUse(t *testing.T) {
	m := libWithTarget(t)
	assert.ErrorIs(t, m.DeleteVersion("5.13.0"), ErrInUse)
	assert.ErrorIs(t, m.DeleteVersion("9.9.9"), ErrNotFound)
	require.NoError(t, m.DeleteVersion("5.12.1"))
	// A pin keeps a version in use until it expires.
	seed(t, m, "5.12.2", deb(digestA))
	exp := time.Now().Add(time.Hour)
	_, err := m.SetPin("u1", 1, "5.12.2", &exp, "admin")
	require.NoError(t, err)
	assert.ErrorIs(t, m.DeleteVersion("5.12.2"), ErrInUse)
	require.NoError(t, m.DeletePin("u1"))
	require.NoError(t, m.DeleteVersion("5.12.2"))
}

func TestDeleteVersionExpiredPinNotInUse(t *testing.T) {
	m := newTestManager(t)
	seed(t, m, "5.12.2", deb(digestA))
	exp := time.Now().Add(50 * time.Millisecond)
	_, err := m.SetPin("u1", 1, "5.12.2", &exp, "admin")
	require.NoError(t, err)
	time.Sleep(80 * time.Millisecond)
	require.NoError(t, m.DeleteVersion("5.12.2"))
}

func TestPutEntriesCannotChangeDigestInUse(t *testing.T) {
	m := libWithTarget(t)
	assert.ErrorIs(t, m.PutEntries("5.13.0", []DigestEntry{deb(digestA)}, "t"), ErrInUse)
	require.NoError(t, m.PutEntries("5.13.0", []DigestEntry{deb(digestB)}, "t"))
	got, err := m.GetEntries("5.13.0")
	require.NoError(t, err)
	assert.Equal(t, digestB, got[0].SHA256)
}

func TestPutEntriesMayAddKeyToInUseVersion(t *testing.T) {
	m := libWithTarget(t)
	rpm := DigestEntry{Platform: "linux", Arch: "amd64", Format: "rpm", SHA256: digestA}
	require.NoError(t, m.PutEntries("5.13.0", []DigestEntry{rpm}, "t"))
	got, err := m.GetEntries("5.13.0")
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestDeleteNodeRecordsRemovesPin(t *testing.T) {
	m := libWithTarget(t)
	_, err := m.SetPin("u1", 1, "5.13.0", nil, "admin")
	require.NoError(t, err)
	require.NoError(t, m.DeleteNodeRecords("u1"))
	p, err := m.GetPin("u1")
	require.NoError(t, err)
	assert.Nil(t, p)
}
