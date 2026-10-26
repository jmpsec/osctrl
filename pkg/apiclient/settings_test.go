package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestGetSettings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer testtoken", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode([]settings.SettingValue{{Name: "n", Service: "tls", Type: settings.TypeString, String: "v"}})
	})
	vals, err := newRealURLServer(t, mux).GetSettings()
	require.NoError(t, err)
	require.Len(t, vals, 1)
	require.Equal(t, "v", vals[0].String)
}

func TestPatchSetting(t *testing.T) {
	mux := http.NewServeMux()
	var got types.SettingPatchRequest
	mux.HandleFunc("PATCH /api/v1/settings/{service}/{name}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("name") == "missing" {
			http.Error(w, `{"error":"setting not found"}`, http.StatusNotFound)
			return
		}
		require.Equal(t, "tls", r.PathValue("service"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	n := int64(7)
	require.NoError(t, api.PatchSetting("tls", "n", types.SettingPatchRequest{Integer: &n}))
	require.NotNil(t, got.Integer)
	require.Equal(t, int64(7), *got.Integer)
	require.Nil(t, got.String)
	err := api.PatchSetting("tls", "missing", types.SettingPatchRequest{Integer: &n})
	require.ErrorContains(t, err, "404")
	require.ErrorContains(t, err, "setting not found")
}
