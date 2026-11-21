package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaReport(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	get := func(user, env, url string) (int, santa.Report) {
		rr := santaDoURL(h.SantaReportHandler, "GET", url, user, "", map[string]string{"env": env})
		var rep santa.Report
		_ = json.Unmarshal(rr.Body.Bytes(), &rep)
		return rr.Code, rep
	}

	code, rep := get("alice", p["env"], "/x")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, santa.DefaultReportDays, rep.Days)
	require.Len(t, rep.TopBlocked, 1)
	require.Equal(t, sha, rep.TopBlocked[0].SHA256)
	require.Len(t, rep.CoverageGaps, 1)

	code, rep = get("alice", p["env"], "/x?days=30")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 30, rep.Days)
	require.Len(t, rep.Trend, 30)

	rr := santaDoURL(h.SantaReportHandler, "GET", "/x?days=7&format=csv", "alice", "", map[string]string{"env": p["env"]})
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "text/csv; charset=utf-8", rr.Header().Get("Content-Type"))
	require.Contains(t, rr.Header().Get("Content-Disposition"), "santa-report-")
	require.True(t, strings.HasPrefix(rr.Body.String(), "list,day,machine_id,"))
	require.Contains(t, rr.Body.String(), "top_blocked,")
	require.Equal(t, http.StatusForbidden, santaDoURL(h.SantaReportHandler, "GET", "/x?format=csv", "dave", "", map[string]string{"env": p["env"]}).Code)

	tests := []struct {
		name, user, env, url string
		code                 int
	}{
		{"requester", "dave", p["env"], "/x", http.StatusForbidden},
		{"admin of another environment only", "alice", "env-b", "/x", http.StatusForbidden},
		{"not a number", "alice", p["env"], "/x?days=two", http.StatusBadRequest},
		{"too long", "alice", p["env"], "/x?days=31", http.StatusBadRequest},
		{"zero", "alice", p["env"], "/x?days=0", http.StatusBadRequest},
	}
	for _, tt := range tests {
		code, _ := get(tt.user, tt.env, tt.url)
		require.Equal(t, tt.code, code, tt.name)
	}
}
