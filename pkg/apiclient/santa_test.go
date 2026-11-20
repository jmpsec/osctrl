package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSantaURLShapes(t *testing.T) {
	var got []string
	held := false
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == http.MethodPut:
			var in SantaModeInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			if held {
				w.WriteHeader(http.StatusAccepted)
				writeJSON(w, map[string]any{"message": "Change 5 needs approval", "pending_change": map[string]any{"id": 5}})
				return
			}
			writeJSON(w, map[string]any{"id": 8, "scope": in.Scope, "scope_value": in.ScopeValue, "client_mode": in.ClientMode})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/v1/santa/dev/config":
			writeJSON(w, map[string]any{"client_mode": "LOCKDOWN", "token_set": true})
		case r.URL.Path == "/api/v1/santa/dev/modes":
			writeJSON(w, []map[string]any{{"id": 4}})
		case r.URL.Path == "/api/v1/santa/dev/file-access-events":
			writeJSON(w, map[string]any{"events": []map[string]any{{"id": 3}}, "total": 1, "page": 2})
		default:
			writeJSON(w, map[string]any{"days": 7, "sha256": "ab"})
		}
	})
	api := newRealURLServer(t, mux)

	cfg, err := api.GetSantaConfig("dev")
	require.NoError(t, err)
	require.True(t, cfg.TokenSet)
	require.Equal(t, "LOCKDOWN", cfg.ClientMode)
	modes, err := api.GetSantaModeOverrides("dev")
	require.NoError(t, err)
	require.Len(t, modes, 1)
	_, err = api.GetSantaReport("dev", 7)
	require.NoError(t, err)
	_, err = api.GetSantaReport("dev", 0)
	require.NoError(t, err)
	fa, err := api.GetSantaFileAccessEvents("dev", "M-1", 2, 50)
	require.NoError(t, err)
	require.Equal(t, int64(1), fa.Total)
	_, err = api.GetSantaBinary("dev", "ab")
	require.NoError(t, err)
	res, err := api.SetSantaModeOverride("dev", SantaModeInput{Scope: "tag", ScopeValue: "pilot", ClientMode: "MONITOR"})
	require.NoError(t, err)
	require.Equal(t, uint(8), res.ID)
	held = true
	res, err = api.SetSantaModeOverride("dev", SantaModeInput{Scope: "tag", ScopeValue: "pilot", ClientMode: "MONITOR"})
	require.NoError(t, err)
	require.Zero(t, res.ID)
	require.Contains(t, res.Message, "needs approval")
	require.NoError(t, api.DeleteSantaModeOverride("dev", 4))

	require.Equal(t, []string{
		"GET /api/v1/santa/dev/config",
		"GET /api/v1/santa/dev/modes",
		"GET /api/v1/santa/dev/reports?days=7",
		"GET /api/v1/santa/dev/reports",
		"GET /api/v1/santa/dev/file-access-events?machine_id=M-1&page=2&page_size=50",
		"GET /api/v1/santa/dev/binaries/ab",
		"PUT /api/v1/santa/dev/modes",
		"PUT /api/v1/santa/dev/modes",
		"DELETE /api/v1/santa/dev/modes/4",
	}, got)
}
