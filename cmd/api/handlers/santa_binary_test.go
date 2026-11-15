package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/stretchr/testify/require"
)

func TestSantaBinary(t *testing.T) {
	h, p, sha := setupSantaRequests(t)
	require.NoError(t, h.Santa.CreateRule(&santa.Rule{EnvironmentID: 1, Identifier: sha, RuleType: "BINARY", Policy: "BLOCKLIST", Scope: "env"}))
	get := func(user, env, sha string) (int, santa.Binary) {
		rr := santaDo(h.SantaBinaryHandler, "GET", user, "", map[string]string{"env": env, "sha256": sha})
		var b santa.Binary
		_ = json.Unmarshal(rr.Body.Bytes(), &b)
		return rr.Code, b
	}

	code, b := get("alice", p["env"], strings.ToUpper(sha))
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, sha, b.SHA256)
	require.Equal(t, "tool", b.FileName)
	require.EqualValues(t, 1, b.Machines)
	require.EqualValues(t, 1, b.Blocked)
	require.Len(t, b.Rules, 1)

	tests := []struct {
		name, user, env, sha string
		code                 int
	}{
		{"requester", "dave", p["env"], sha, http.StatusForbidden},
		{"admin of another environment only", "alice", "env-b", sha, http.StatusForbidden},
		{"bad hash", "alice", p["env"], "nope", http.StatusBadRequest},
		{"hash never seen", "alice", p["env"], strings.Repeat("00", 32), http.StatusNotFound},
	}
	for _, tt := range tests {
		code, _ := get(tt.user, tt.env, tt.sha)
		require.Equal(t, tt.code, code, tt.name)
	}
}
