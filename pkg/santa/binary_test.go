package santa

import (
	"strings"
	"testing"
	"time"

	syncv1 "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/sync"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestBinary(t *testing.T) {
	m := newTestManager(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	m.now = func() time.Time { return now }
	n := testNode()
	mustPreflight(t, m, n, false)
	sha := strings.Repeat("a1", 32)
	const team, signing, cdhash, leaf = "ABCDE12345", "ABCDE12345:com.example.tool", "0123456789abcdef0123456789abcdef01234567", "LEAFCERT"
	leafSHA := strings.Repeat("c3", 32)
	chain := []*syncv1.Certificate{
		{Sha256: strings.ToUpper(leafSHA), Cn: leaf, Org: "Example Inc", Ou: team, ValidFrom: 1700000000, ValidUntil: 1800000000},
		nil,
		{Sha256: strings.Repeat("d4", 32), Cn: "Developer ID Certification Authority"},
	}
	_, err := m.EventUpload(n, &syncv1.EventUploadRequest{Events: []*syncv1.Event{
		{FileSha256: strings.ToUpper(sha), FileName: "old-name", Decision: syncv1.Decision_BLOCK_UNKNOWN, ExecutionTime: 1000},
		{
			FileSha256: sha, FileName: "tool", FilePath: "/Applications/Tool.app/Contents/MacOS", Decision: syncv1.Decision_ALLOW_BINARY,
			ExecutionTime: 3000, TeamId: team, SigningId: signing, Cdhash: cdhash, SigningChain: chain,
			FileBundleId: "com.example.tool", FileBundleName: "Tool", FileBundleVersion: "42", FileBundleVersionString: "1.2.3",
			FileBundlePath: "/Applications/Tool.app",
		},
		{FileSha256: strings.Repeat("ff", 32), FileName: "other", Decision: syncv1.Decision_BLOCK_UNKNOWN, ExecutionTime: 5000},
	}})
	require.NoError(t, err)
	// The same file on a second machine, and in another environment.
	now = t0.Add(time.Hour)
	other := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, m.AddEvents([]Event{
		{EnvironmentID: 1, MachineID: other, FileSHA256: sha, Decision: "BLOCK_UNKNOWN", ExecutedAt: time.Unix(2000, 0).UTC()},
		{EnvironmentID: 2, MachineID: other, FileSHA256: sha, Decision: "BLOCK_UNKNOWN", ExecutedAt: time.Unix(1, 0).UTC()},
	}))
	rules := []Rule{
		{Identifier: sha, RuleType: "BINARY", Policy: "ALLOWLIST", Scope: "node", ScopeValue: other},
		{Identifier: team, RuleType: "TEAMID", Policy: "BLOCKLIST", Scope: "tag", ScopeValue: "dev"},
		{Identifier: signing, RuleType: "SIGNINGID", Policy: "ALLOWLIST", Scope: "env"},
		{Identifier: cdhash, RuleType: "CDHASH", Policy: "ALLOWLIST", Scope: "env"},
		{Identifier: leafSHA, RuleType: "CERTIFICATE", Policy: "ALLOWLIST", Scope: "env"},
		{Identifier: strings.Repeat("ff", 32), RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "env"},
		{Identifier: "ZZZZZ99999", RuleType: "TEAMID", Policy: "BLOCKLIST", Scope: "env"},
	}
	for i := range rules {
		rules[i].EnvironmentID = 1
		require.NoError(t, m.CreateRule(&rules[i]))
	}

	b, err := m.Binary(1, strings.ToUpper(sha))
	require.NoError(t, err)
	require.Equal(t, sha, b.SHA256)
	// Identity comes from the newest event.
	require.Equal(t, []string{"tool", team, signing, cdhash, "com.example.tool", "Tool", "1.2.3", "/Applications/Tool.app"},
		[]string{b.FileName, b.TeamID, b.SigningID, b.CDHash, b.BundleID, b.BundleName, b.BundleVersion, b.BundlePath})
	require.Len(t, b.SigningChain, 2)
	require.Equal(t, Cert{
		SHA256: strings.ToUpper(leafSHA), CN: leaf, Org: "Example Inc", OU: team,
		ValidFrom: time.Unix(1700000000, 0).UTC(), ValidUntil: time.Unix(1800000000, 0).UTC(),
	}, b.SigningChain[0])
	// First and last seen are when osctrl received the events, not the client clock.
	require.True(t, b.FirstSeen.Equal(t0), b.FirstSeen)
	require.True(t, b.LastSeen.Equal(t0.Add(time.Hour)), b.LastSeen)
	require.EqualValues(t, 3, b.Events)
	require.EqualValues(t, 2, b.Blocked)
	require.EqualValues(t, 2, b.Machines)
	var matched []string
	for _, r := range b.Rules {
		matched = append(matched, r.RuleType)
	}
	require.ElementsMatch(t, []string{"BINARY", "TEAMID", "SIGNINGID", "CDHASH", "CERTIFICATE"}, matched)

	// An unsigned file: no chain, only its own hash rule.
	b, err = m.Binary(1, strings.Repeat("ff", 32))
	require.NoError(t, err)
	require.Empty(t, b.SigningChain)
	require.Len(t, b.Rules, 1)

	_, err = m.Binary(1, strings.Repeat("00", 32))
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	_, err = m.Binary(3, sha)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	_, err = m.Binary(1, "nope")
	require.ErrorIs(t, err, ErrInvalidRequest)
}

func TestSigningChainIsBounded(t *testing.T) {
	certs := make([]*syncv1.Certificate, maxChainCerts+5)
	for i := range certs {
		certs[i] = &syncv1.Certificate{Sha256: strings.Repeat("a", 200), Cn: strings.Repeat("n", 1000)}
	}
	chain := signingChain(certs)
	require.Len(t, chain, maxChainCerts)
	require.Len(t, chain[0].SHA256, 64)
	require.Len(t, chain[0].CN, maxEventField)
	require.Nil(t, signingChain(nil))
}

func TestBinaryHistory(t *testing.T) {
	m := newTestManager(t)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := t0
	m.now = func() time.Time { return now }
	sha := strings.Repeat("b2", 32)
	a, c := strings.ToUpper(testUUID), "11111111-2222-3333-4444-555555555555"
	require.NoError(t, m.SaveMachine(&Machine{EnvironmentID: 1, MachineID: a, Hostname: "mac-a"}))
	ev := func(machine, decision, name string) Event {
		return Event{EnvironmentID: 1, MachineID: machine, FileSHA256: strings.ToUpper(sha), FileName: name, Decision: decision}
	}
	require.NoError(t, m.AddEvents([]Event{ev(a, "BLOCK_UNKNOWN", "tool"), ev(a, "ALLOW_UNKNOWN", "tool"), ev(c, DecisionBundleBinary, "x")}))
	now = t0.Add(48 * time.Hour)
	require.NoError(t, m.AddEvents([]Event{ev(a, "ALLOW_BINARY", "tool-2"), ev(c, "BLOCK_BINARY", "tool")}))

	// Events age out; the history stays.
	gone, err := m.PruneEvents(now.Add(time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 5, gone)
	b, err := m.Binary(1, sha)
	require.NoError(t, err, "first seen survives event pruning")
	require.True(t, b.FirstSeen.Equal(t0), b.FirstSeen)
	require.True(t, b.LastSeen.Equal(now), b.LastSeen)
	require.EqualValues(t, 2, b.Machines, "a bundle listing is not an execution")
	require.Zero(t, b.Events, "event counts cover kept events only")
	require.Zero(t, b.LatestEventID)
	require.Len(t, b.MachineList, 2)
	byID := map[string]BinaryMachine{}
	for _, bm := range b.MachineList {
		byID[bm.MachineID] = bm
	}
	require.Equal(t, "mac-a", byID[a].Hostname)
	require.EqualValues(t, 3, byID[a].Events)
	require.Equal(t, "tool-2", byID[a].FileName)
	require.True(t, byID[a].FirstSeen.Equal(t0))
	require.Empty(t, byID[c].Hostname, "machine no longer known")
	require.EqualValues(t, 1, byID[c].Events)
	require.True(t, byID[c].FirstSeen.Equal(now))
	require.Contains(t, []string{"tool", "tool-2"}, b.FileName, "name from the newest machine row when no event is kept")

	// A hash rule still matches after pruning.
	require.NoError(t, m.CreateRule(&Rule{EnvironmentID: 1, Identifier: sha, RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "env"}))
	b, err = m.Binary(1, sha)
	require.NoError(t, err)
	require.Len(t, b.Rules, 1)
	_, err = m.Binary(2, sha)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestBinaryHistoryBackfill(t *testing.T) {
	m := newTestManager(t)
	sha := strings.Repeat("c3", 32)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Events stored before the history existed.
	require.NoError(t, m.DB.Create(&[]Event{
		{EnvironmentID: 1, MachineID: "M-1", FileSHA256: strings.ToUpper(sha), FileName: "t", Decision: "BLOCK_UNKNOWN", CreatedAt: t0},
		{EnvironmentID: 1, MachineID: "M-1", FileSHA256: sha, FileName: "t", Decision: "BLOCK_UNKNOWN", CreatedAt: t0.Add(time.Hour)},
		{EnvironmentID: 1, MachineID: "M-2", FileSHA256: sha, Decision: DecisionBundleBinary, CreatedAt: t0},
	}).Error)
	require.NoError(t, m.DB.Migrator().DropTable(&BinaryMachine{}))
	require.NoError(t, Migrate(m.DB))
	require.NoError(t, Migrate(m.DB), "a second migration adds nothing")
	var rows []BinaryMachine
	require.NoError(t, m.DB.Find(&rows).Error)
	require.Len(t, rows, 1)
	require.Equal(t, sha, rows[0].SHA256)
	require.EqualValues(t, 2, rows[0].Events)
	require.True(t, rows[0].FirstSeen.Equal(t0), rows[0].FirstSeen)
	require.True(t, rows[0].LastSeen.Equal(t0.Add(time.Hour)), rows[0].LastSeen)
}
