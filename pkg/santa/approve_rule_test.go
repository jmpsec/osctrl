package santa

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApproveRuleTypes(t *testing.T) {
	m := newTestManager(t)
	machine := strings.ToUpper(testUUID)
	sha := strings.Repeat("ab", 32)
	cert := strings.Repeat("cd", 32)
	bundle := strings.Repeat("ef", 32)
	other := strings.Repeat("01", 32)
	require.NoError(t, m.AddEvents([]Event{
		{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_UNKNOWN", FileSHA256: sha, FileName: "tool",
			TeamID: "EQHXZ8M8AV", SigningID: "EQHXZ8M8AV:com.example.tool", BundleHash: bundle,
			SigningChain: []Cert{{SHA256: cert, CN: "Developer ID Application: Example"}}},
		// The client uploads the bundle's binaries; one is the file itself, one is junk.
		{EnvironmentID: 1, MachineID: machine, Decision: DecisionBundleBinary, FileSHA256: sha, BundleHash: bundle},
		{EnvironmentID: 1, MachineID: machine, Decision: DecisionBundleBinary, FileSHA256: other, BundleHash: bundle},
		{EnvironmentID: 1, MachineID: machine, Decision: DecisionBundleBinary, FileSHA256: "not-a-hash", BundleHash: bundle},
		// Same bundle in another environment: not ours.
		{EnvironmentID: 2, MachineID: machine, Decision: DecisionBundleBinary, FileSHA256: strings.Repeat("02", 32), BundleHash: bundle},
	}))
	ask := func() Request {
		t.Helper()
		req, created, err := m.CreateRequest(1, machine, sha, "dave", "need it")
		require.NoError(t, err)
		require.True(t, created)
		return req
	}

	req := ask()
	reqs, err := m.Requests(1, RequestPending, "")
	require.NoError(t, err)
	require.Equal(t, cert, reqs[0].CertSHA256)
	require.Equal(t, 3, reqs[0].BundleBinaries, "as uploaded; rules skip what is not a hash")
	// The queue shows the carve of the request's event, for carving from it.
	require.Empty(t, reqs[0].Carve)
	require.NoError(t, m.SetEventCarve(1, reqs[0].EventID, "carve-1"))
	reqs, err = m.Requests(1, RequestPending, "")
	require.NoError(t, err)
	require.Equal(t, "carve-1", reqs[0].Carve)

	for _, tt := range []struct {
		ruleType, want string
	}{
		{"TEAMID", "EQHXZ8M8AV"},
		{"SIGNINGID", "EQHXZ8M8AV:com.example.tool"},
		{"CERTIFICATE", cert},
		{"", sha},
	} {
		decided, err := m.DecideRequest(1, req.ID, Decision{Approve: true, Scope: "env", By: "alice", RuleType: tt.ruleType})
		require.NoError(t, err, tt.ruleType)
		require.Equal(t, RequestApproved, decided.Status)
		rules, err := m.Rules(1)
		require.NoError(t, err)
		var rule Rule
		for _, r := range rules {
			if r.ID == decided.RuleID {
				rule = r
			}
		}
		require.Equal(t, tt.want, rule.Identifier, tt.ruleType)
		require.Equal(t, "ALLOWLIST", rule.Policy)
		stored, err := m.Request(1, req.ID)
		require.NoError(t, err)
		require.Equal(t, rule.RuleType, stored.RuleType)
		req = ask()
	}

	// A bundle approval allows the file and its other valid binaries, on the machine.
	decided, err := m.DecideRequest(1, req.ID, Decision{Approve: true, Scope: "node", By: "alice", Bundle: true})
	require.NoError(t, err)
	rules, err := m.Rules(1)
	require.NoError(t, err)
	var node []string
	for _, r := range rules {
		if r.Scope == "node" {
			node = append(node, r.Identifier)
		}
	}
	require.ElementsMatch(t, []string{sha, other}, node)
	require.Equal(t, "BINARY", decided.RuleType)

	// Choices the file cannot back are refused and leave the request pending.
	req = ask()
	for _, d := range []Decision{
		{RuleType: "TEAMID", Bundle: true},
		{RuleType: "CDHASH"},
		{RuleType: "binary; DROP"},
	} {
		d.Approve, d.Scope, d.By = true, "node", "alice"
		_, err := m.DecideRequest(1, req.ID, d)
		require.ErrorIs(t, err, ErrInvalidRequest, d.RuleType)
	}
	unsigned := strings.Repeat("99", 32)
	require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, Decision: "BLOCK_UNKNOWN", FileSHA256: unsigned}}))
	plain, _, err := m.CreateRequest(1, machine, unsigned, "dave", "need it")
	require.NoError(t, err)
	for _, d := range []Decision{{RuleType: "TEAMID"}, {RuleType: "SIGNINGID"}, {RuleType: "CERTIFICATE"}, {Bundle: true}} {
		d.Approve, d.Scope, d.By = true, "node", "alice"
		_, err := m.DecideRequest(1, plain.ID, d)
		require.ErrorIs(t, err, ErrInvalidRequest, d.RuleType)
	}
	stored, err := m.Request(1, plain.ID)
	require.NoError(t, err)
	require.Equal(t, RequestPending, stored.Status)
}
