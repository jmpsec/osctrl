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
	require.Equal(t, int64(1000), b.FirstSeen.Unix())
	require.Equal(t, int64(3000), b.LastSeen.Unix())
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
