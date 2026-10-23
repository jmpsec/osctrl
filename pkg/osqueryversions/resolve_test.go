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
	_, err = m.ClearEnvTarget(1)
	require.NoError(t, err)
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
	_, err = m.DeletePin("u1")
	require.NoError(t, err)
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
	_, err = m.DeletePin("u1")
	require.NoError(t, err)
	require.NoError(t, m.DeleteVersion("5.12.2"))
}

func TestDeleteVersionExpiredPinNotInUse(t *testing.T) {
	m := newTestManager(t)
	seed(t, m, "5.12.2", deb(digestA))
	past := time.Now().Add(-time.Minute)
	require.NoError(t, m.db.Create(&NodePin{NodeUUID: "u1", EnvironmentID: 1, Version: "5.12.2", RequestID: "r", ExpiresAt: &past}).Error)
	require.NoError(t, m.DeleteVersion("5.12.2"))
}

// SQLite stores times as text with their zone offset: an unexpired pin stored
// in a far-west offset sorts before now as text, yet keeps the version in use.
func TestDeleteVersionPinExpiryInOtherZoneStillInUse(t *testing.T) {
	m := newTestManager(t)
	seed(t, m, "5.12.2", deb(digestA))
	exp := time.Now().Add(time.Hour).In(time.FixedZone("west", -12*3600))
	require.NoError(t, m.db.Create(&NodePin{NodeUUID: "u1", EnvironmentID: 1, Version: "5.12.2", RequestID: "r", ExpiresAt: &exp}).Error)
	assert.ErrorIs(t, m.DeleteVersion("5.12.2"), ErrInUse)
	assert.ErrorIs(t, m.PutEntries("5.12.2", []DigestEntry{deb(digestB)}, "t"), ErrInUse)
}

func TestPinExpiringExactlyNowIsExpired(t *testing.T) {
	at := now
	assert.True(t, NodePin{ExpiresAt: &at}.Expired(now))
	assert.False(t, NodePin{}.Expired(now))
}

func TestResolvePinOfOtherEnvironmentFallsBackToTarget(t *testing.T) {
	m := libWithTarget(t)
	seed(t, m, "5.12.2", deb(digestA))
	_, err := m.SetPin("u1", 2, "5.12.2", nil, "admin")
	require.NoError(t, err)
	r, err := m.Resolve(linuxIn("5.12.1"), now)
	require.NoError(t, err)
	assert.Equal(t, "environment", r.Source)
	assert.Equal(t, "5.13.0", r.Target.Version)
}

func TestPutEntriesCannotChangeDigestPinned(t *testing.T) {
	m := newTestManager(t)
	seed(t, m, "5.12.2", deb(digestA))
	exp := time.Now().Add(time.Hour)
	_, err := m.SetPin("u1", 1, "5.12.2", &exp, "admin")
	require.NoError(t, err)
	assert.ErrorIs(t, m.PutEntries("5.12.2", []DigestEntry{deb(digestB)}, "t"), ErrInUse)
}

func TestPutEntriesRejectsTooManyOrDuplicateEntries(t *testing.T) {
	m := newTestManager(t)
	dup := []DigestEntry{deb(digestA), deb(digestB)}
	assert.ErrorIs(t, m.PutEntries("5.12.1", dup, "t"), ErrInvalid)
	six := []DigestEntry{
		{Platform: "linux", Arch: "amd64", Format: "deb", SHA256: digestA},
		{Platform: "linux", Arch: "arm64", Format: "deb", SHA256: digestA},
		{Platform: "linux", Arch: "amd64", Format: "rpm", SHA256: digestA},
		{Platform: "linux", Arch: "arm64", Format: "rpm", SHA256: digestA},
		{Platform: "darwin", Arch: "universal", Format: "pkg", SHA256: digestA},
		{Platform: "darwin", Arch: "universal", Format: "pkg", SHA256: digestB},
	}
	assert.ErrorIs(t, m.PutEntries("5.12.1", six, "t"), ErrInvalid)
	require.NoError(t, m.PutEntries("5.12.1", six[:5], "t"))
}

func TestSetPinRequestID(t *testing.T) {
	m := libWithTarget(t)
	exp := time.Now().Add(time.Hour)
	first, err := m.SetPin("u1", 1, "5.13.0", &exp, "admin")
	require.NoError(t, err)
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{32}$`), first.RequestID, "first pin gets one")

	// Changing only the expiry keeps it: a rejected target is not retried.
	later := exp.Add(time.Hour)
	p, err := m.SetPin("u1", 1, "5.13.0", &later, "bob")
	require.NoError(t, err)
	assert.Equal(t, first.RequestID, p.RequestID, "expiry change")
	assert.Equal(t, "bob", p.UpdatedBy)
	assert.True(t, later.Equal(*p.ExpiresAt))
	p, err = m.SetPin("u1", 1, "5.13.0", nil, "bob")
	require.NoError(t, err)
	assert.Equal(t, first.RequestID, p.RequestID, "expiry removed")
	p, err = m.SetPin("u1", 1, "5.13.0", &later, "bob")
	require.NoError(t, err)
	assert.Equal(t, first.RequestID, p.RequestID, "expiry added")
	got, err := m.GetPin("u1")
	require.NoError(t, err)
	assert.Equal(t, first.RequestID, got.RequestID)
	assert.True(t, later.Equal(*got.ExpiresAt))

	// An identical re-save retries.
	again, err := m.SetPin("u1", 1, "5.13.0", &later, "bob")
	require.NoError(t, err)
	assert.NotEqual(t, first.RequestID, again.RequestID, "identical re-save")
	noExp, err := m.SetPin("u1", 1, "5.13.0", nil, "bob")
	require.NoError(t, err)
	same, err := m.SetPin("u1", 1, "5.13.0", nil, "bob")
	require.NoError(t, err)
	assert.NotEqual(t, noExp.RequestID, same.RequestID, "identical re-save without expiry")

	// Another version gets a new one.
	other, err := m.SetPin("u1", 1, "5.12.1", nil, "bob")
	require.NoError(t, err)
	assert.NotEqual(t, same.RequestID, other.RequestID, "different version")
}

func TestClearEnvTargetAndDeletePinReportRemoval(t *testing.T) {
	m := libWithTarget(t)
	removed, err := m.ClearEnvTarget(1)
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = m.ClearEnvTarget(1)
	require.NoError(t, err)
	assert.False(t, removed)
	_, err = m.SetPin("u1", 1, "5.13.0", nil, "admin")
	require.NoError(t, err)
	removed, err = m.DeletePin("u1")
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = m.DeletePin("u1")
	require.NoError(t, err)
	assert.False(t, removed)
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

// A pin row left by another environment is a first pin for the new one.
func TestSetPinOtherEnvironmentGetsNewRequestID(t *testing.T) {
	m := libWithTarget(t)
	e1 := time.Now().Add(time.Hour)
	a, err := m.SetPin("u1", 2, "5.13.0", &e1, "admin")
	require.NoError(t, err)
	e2 := e1.Add(time.Hour)
	b, err := m.SetPin("u1", 1, "5.13.0", &e2, "admin")
	require.NoError(t, err)
	assert.NotEqual(t, a.RequestID, b.RequestID)
	assert.Equal(t, uint(1), b.EnvironmentID)
}

func TestSameExpiryTolerance(t *testing.T) {
	base := time.Date(2030, 1, 1, 10, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := base.Add(d); return &x }
	for name, c := range map[string]struct {
		a, b *time.Time
		want bool
	}{
		"both nil":                    {nil, nil, true},
		"nil vs set":                  {nil, at(0), false},
		"equal":                       {at(0), at(0), true},
		".4s apart across a boundary": {at(800 * time.Millisecond), at(1200 * time.Millisecond), true},
		".9995 rounded up by the DB":  {at(999500 * time.Microsecond), at(time.Second), true},
		".9999 rounded up by the DB":  {at(999900 * time.Microsecond), at(time.Second), true},
		"1.5s apart":                  {at(0), at(1500 * time.Millisecond), false},
		"1.5s apart, reversed":        {at(1500 * time.Millisecond), at(0), false},
	} {
		assert.Equal(t, c.want, sameExpiry(c.a, c.b), name)
	}
}
