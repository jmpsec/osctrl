package santa

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeCheck struct {
	name    string
	verdict string
	err     error
	calls   atomic.Int32
}

func (f *fakeCheck) Name() string { return f.name }
func (f *fakeCheck) Check(_ context.Context, _ string) (string, string, error) {
	f.calls.Add(1)
	return f.verdict, "detail\nwith a newline", f.err
}

func riskManager(t *testing.T, checks ...RiskCheck) (*Manager, *time.Time) {
	t.Helper()
	m := newTestManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	m.Risk = &RiskEngine{Checks: checks, TTL: time.Hour, Timeout: time.Second}
	return m, &now
}

func TestCheckRiskCachesAndAggregates(t *testing.T) {
	sha := strings.Repeat("a1", 32)
	vt := &fakeCheck{name: "virustotal", verdict: RiskClean}
	hook := &fakeCheck{name: "webhook", verdict: RiskUnknown}
	m, now := riskManager(t, vt, hook)

	cached, err := m.cachedRisk(1, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskUnchecked, cached[sha].Verdict)

	risk, err := m.CheckRisk(context.Background(), 1, strings.ToUpper(sha))
	require.NoError(t, err)
	require.Equal(t, RiskClean, risk.Verdict)
	require.Len(t, risk.Checks, 2)
	for _, c := range risk.Checks {
		require.NotContains(t, c.Detail, "\n")
	}
	// Cached: no second call until the TTL runs out.
	_, err = m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.EqualValues(t, 1, vt.calls.Load())
	cached, err = m.cachedRisk(1, []string{sha})
	require.NoError(t, err)
	require.Equal(t, RiskClean, cached[sha].Verdict)

	*now = now.Add(time.Hour)
	vt.verdict = RiskFlagged
	risk, err = m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.Equal(t, RiskFlagged, risk.Verdict)
	require.EqualValues(t, 2, vt.calls.Load())
	n, err := m.PruneVerdicts(now.Add(2 * time.Hour))
	require.NoError(t, err)
	require.EqualValues(t, 2, n)

	_, err = m.CheckRisk(context.Background(), 1, "nope")
	require.ErrorIs(t, err, ErrInvalidRequest)
	m.Risk = nil
	risk, err = m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.Nil(t, risk)
}

func TestCheckRiskErrorsAreShortLived(t *testing.T) {
	sha := strings.Repeat("b2", 32)
	down := &fakeCheck{name: "webhook", err: errors.New("dial tcp: connection refused")}
	bogus := &fakeCheck{name: "virustotal", verdict: "maybe"}
	m, now := riskManager(t, down, bogus)
	risk, err := m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.Equal(t, RiskError, risk.Verdict)
	for _, c := range risk.Checks {
		require.Equal(t, RiskError, c.Verdict)
		require.Equal(t, now.Add(riskErrorTTL).Unix(), c.ExpiresAt.Unix())
	}
	*now = now.Add(riskErrorTTL)
	down.err, down.verdict, bogus.verdict = nil, RiskClean, RiskClean
	risk, err = m.CheckRisk(context.Background(), 1, sha)
	require.NoError(t, err)
	require.Equal(t, RiskClean, risk.Verdict)
}

func TestAggregate(t *testing.T) {
	v := func(s ...string) []Verdict {
		out := []Verdict{}
		for _, x := range s {
			out = append(out, Verdict{Verdict: x})
		}
		return out
	}
	tests := []struct {
		in   []Verdict
		want string
	}{
		{nil, RiskUnchecked},
		{v(RiskClean, RiskFlagged, RiskError), RiskFlagged},
		{v(RiskClean, RiskError), RiskError},
		{v(RiskUnknown, RiskClean), RiskClean},
		{v(RiskUnknown, RiskUnknown), RiskUnknown},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, aggregate(tt.in), "%v", tt.in)
	}
}

func TestVoteFailsClosedOnRisk(t *testing.T) {
	check := &fakeCheck{name: "virustotal", verdict: RiskFlagged}
	m, now := riskManager(t, check)
	machine := strings.ToUpper(testUUID)
	sha := strings.Repeat("c3", 32)
	require.NoError(t, m.SaveConfig(EnvConfig{EnvironmentID: 1, ClientMode: "LOCKDOWN", ApprovalURL: "https://osctrl.example.com", VoteGlobalThreshold: 1}))
	require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, FileSHA256: sha, Decision: "BLOCK_UNKNOWN"}}))

	_, err := m.Vote(1, machine, sha, "bob")
	require.ErrorIs(t, err, ErrRiskFlagged)
	*now = now.Add(time.Hour)
	check.verdict, check.err = "", errors.New("timeout")
	_, err = m.Vote(1, machine, sha, "bob")
	require.ErrorIs(t, err, ErrRiskUnavailable)
	st, err := m.VoteStatus(1, sha, "bob")
	require.NoError(t, err)
	require.Zero(t, st.Votes, "refused votes are not counted")

	// "Unknown to the check" is not an outage: the vote goes through.
	*now = now.Add(time.Hour)
	check.verdict, check.err = RiskUnknown, nil
	res, err := m.Vote(1, machine, sha, "bob")
	require.NoError(t, err)
	require.Len(t, res.Rules, 1)
}

func TestApprovalNeedsOverrideWhenFlagged(t *testing.T) {
	check := &fakeCheck{name: "virustotal", verdict: RiskFlagged}
	m, now := riskManager(t, check)
	machine := strings.ToUpper(testUUID)
	shas := []string{strings.Repeat("d4", 32), strings.Repeat("e5", 32)}
	for _, s := range shas {
		require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, FileSHA256: s, Decision: "BLOCK_UNKNOWN"}}))
	}
	req, _, err := m.CreateRequest(1, machine, shas[0], "bob", "need it")
	require.NoError(t, err)

	approve := Decision{Approve: true, By: "alice", Scope: "node"}
	_, err = m.DecideRequest(1, req.ID, approve)
	require.ErrorIs(t, err, ErrRiskFlagged)
	approve.Override = true
	_, err = m.DecideRequest(1, req.ID, approve)
	require.ErrorIs(t, err, ErrOverrideReason)
	reqs, err := m.Requests(1, RequestPending, "")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	require.Equal(t, RiskFlagged, reqs[0].Risk.Verdict, "the queue shows the cached verdict")

	approve.Reason = "internal build, false positive"
	got, err := m.DecideRequest(1, req.ID, approve)
	require.NoError(t, err)
	require.Equal(t, RequestApproved, got.Status)
	require.True(t, got.RiskOverride)
	stored, err := m.Request(1, req.ID)
	require.NoError(t, err)
	require.True(t, stored.RiskOverride)

	// A failed check is shown but does not stop the approver; denying never checks.
	*now = now.Add(time.Hour)
	check.verdict, check.err = "", errors.New("quota exceeded")
	req, _, err = m.CreateRequest(1, machine, shas[1], "bob", "need it")
	require.NoError(t, err)
	calls := check.calls.Load()
	_, err = m.DecideRequest(1, req.ID, Decision{By: "alice", Reason: "no"})
	require.NoError(t, err)
	require.Equal(t, calls, check.calls.Load())
	req2, _, err := m.CreateRequest(1, machine, shas[1], "bob", "again")
	require.NoError(t, err)
	got, err = m.DecideRequest(1, req2.ID, Decision{Approve: true, By: "alice", Scope: "node"})
	require.NoError(t, err)
	require.False(t, got.RiskOverride)
}

func TestApprovalByLinkChecksRisk(t *testing.T) {
	check := &fakeCheck{name: "webhook", verdict: RiskFlagged}
	m, _ := riskManager(t, check)
	machine := strings.ToUpper(testUUID)
	sha := strings.Repeat("f6", 32)
	require.NoError(t, m.AddEvents([]Event{{EnvironmentID: 1, MachineID: machine, FileSHA256: sha, Decision: "BLOCK_UNKNOWN"}}))
	req, _, err := m.CreateRequest(1, machine, sha, "bob", "need it")
	require.NoError(t, err)
	approve, _, err := m.NewRequestLinks(req)
	require.NoError(t, err)
	_, err = m.DecideByLink(1, approve, Decision{Approve: true, By: "alice", Scope: "node"})
	require.ErrorIs(t, err, ErrRiskFlagged)
	// The refused attempt leaves the link usable.
	got, err := m.DecideByLink(1, approve, Decision{Approve: true, By: "alice", Scope: "node", Override: true, Reason: "signed in-house"})
	require.NoError(t, err)
	require.True(t, got.RiskOverride)
	_, err = m.DecideByLink(1, "nope", Decision{Approve: true, By: "alice", Scope: "node"})
	require.ErrorIs(t, err, ErrLinkInvalid)
}

func TestVirusTotalCheck(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	var gotPath, gotKey string
	status, body := http.StatusOK, `{"data":{"attributes":{"last_analysis_stats":{"malicious":4,"suspicious":1,"undetected":60,"harmless":5}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey = r.URL.Path, r.Header.Get("x-apikey")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	vt := VirusTotal{Key: "vt-key", Threshold: 3, BaseURL: srv.URL, Client: srv.Client()}

	verdict, detail, err := vt.Check(context.Background(), sha)
	require.NoError(t, err)
	require.Equal(t, "/api/v3/files/"+sha, gotPath)
	require.Equal(t, "vt-key", gotKey)
	require.Equal(t, RiskFlagged, verdict)
	require.Equal(t, "4 of 70 engines flag it", detail)

	vt.Threshold = 5
	verdict, _, err = vt.Check(context.Background(), sha)
	require.NoError(t, err)
	require.Equal(t, RiskClean, verdict)

	status = http.StatusNotFound
	verdict, _, err = vt.Check(context.Background(), sha)
	require.NoError(t, err)
	require.Equal(t, RiskUnknown, verdict)
	for _, s := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusBadGateway} {
		status = s
		_, _, err = vt.Check(context.Background(), sha)
		require.Error(t, err, s)
		require.NotContains(t, err.Error(), "vt-key")
	}
	status, body = http.StatusOK, "not json"
	_, _, err = vt.Check(context.Background(), sha)
	require.Error(t, err)
}

func TestRiskWebhookCheck(t *testing.T) {
	sha := strings.Repeat("cd", 32)
	var got map[string]string
	var gotSig string
	reply := `{"verdict":"flagged","detail":"known bad"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Osctrl-Signature")
		mac := hmac.New(sha256.New, []byte("s3cret"))
		mac.Write(raw)
		if gotSig != hex.EncodeToString(mac.Sum(nil)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.Unmarshal(raw, &got)
		_, _ = io.WriteString(w, reply)
	}))
	defer srv.Close()
	hook := RiskWebhook{URL: srv.URL + "/check?token=url-secret", Secret: "s3cret", Client: srv.Client()}

	verdict, detail, err := hook.Check(context.Background(), sha)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"sha256": sha}, got, "only the hash is sent")
	require.Equal(t, []string{RiskFlagged, "known bad"}, []string{verdict, detail})

	hook.Secret = "wrong"
	_, _, err = hook.Check(context.Background(), sha)
	require.ErrorContains(t, err, "401")

	srv.Close()
	_, _, err = hook.Check(context.Background(), sha)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "url-secret", "the URL may carry a token")
}
