package apiclient

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestGetEnvConfig(t *testing.T) {
	mux := http.NewServeMux()
	var gotEnv string
	mux.HandleFunc("GET /api/v1/environments/config/{env}", func(w http.ResponseWriter, r *http.Request) {
		gotEnv = r.PathValue("env")
		if gotEnv == "nope" {
			http.Error(w, `{"error":"no access"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(types.EnvConfigResponse{Schedule: `{"q":{}}`, Options: `{}`})
	})
	api := newRealURLServer(t, mux)
	cnf, err := api.GetEnvConfig("a b")
	require.NoError(t, err)
	require.Equal(t, "a b", gotEnv)
	require.Equal(t, `{"q":{}}`, cnf.Schedule)
	_, err = api.GetEnvConfig("nope")
	require.ErrorContains(t, err, "403")
	require.ErrorContains(t, err, "no access")
}

func TestPatchEnvConfig(t *testing.T) {
	mux := http.NewServeMux()
	var got map[string]*string
	mux.HandleFunc("PATCH /api/v1/environments/config/{env}", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "dev", r.PathValue("env"))
		got = nil
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		if v := got["schedule"]; v != nil && *v == "bad" {
			http.Error(w, `{"error":"section \"schedule\" is not valid JSON"}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	for _, section := range []string{"options", "schedule", "packs", "decorators", "atc", "flags"} {
		require.NoError(t, api.PatchEnvConfig("dev", section, `{"x":1}`), section)
		require.Len(t, got, 1, "only the edited section is sent")
		require.NotNil(t, got[section], section)
		require.Equal(t, `{"x":1}`, *got[section])
	}
	err := api.PatchEnvConfig("dev", "schedule", "bad")
	require.ErrorContains(t, err, "400")
	require.ErrorContains(t, err, "not valid JSON")
	require.ErrorContains(t, api.PatchEnvConfig("dev", "bogus", "{}"), "unknown configuration section")
}
