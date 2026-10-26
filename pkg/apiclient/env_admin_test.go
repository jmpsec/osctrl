package apiclient

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

// forbidden answers like the API does for a token without the permission.
func forbidden(w http.ResponseWriter) {
	http.Error(w, `{"error":"permission check failed"}`, http.StatusForbidden)
}

func TestCreateEnvironment(t *testing.T) {
	mux := http.NewServeMux()
	var got types.EnvCreateRequest
	mux.HandleFunc("POST /api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		if got.Name == "taken" {
			http.Error(w, `{"error":"environment with that name already exists"}`, http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(environments.TLSEnvironment{UUID: "u-1", Name: got.Name, Hostname: got.Hostname})
	})
	api := newRealURLServer(t, mux)
	env, err := api.CreateEnvironment(types.EnvCreateRequest{Name: "dev", Hostname: "dev.example.com"})
	require.NoError(t, err)
	require.Equal(t, types.EnvCreateRequest{Name: "dev", Hostname: "dev.example.com"}, got)
	require.Equal(t, "u-1", env.UUID)
	require.Equal(t, "dev", env.Name)
	_, err = api.CreateEnvironment(types.EnvCreateRequest{Name: "taken", Hostname: "h"})
	require.ErrorContains(t, err, "409")
	require.ErrorContains(t, err, "already exists")
}

func TestPatchEnvironment(t *testing.T) {
	mux := http.NewServeMux()
	var got map[string]interface{}
	var gotEnv string
	mux.HandleFunc("PATCH /api/v1/environments/{env}", func(w http.ResponseWriter, r *http.Request) {
		gotEnv = r.PathValue("env")
		if gotEnv == "nope" {
			forbidden(w)
			return
		}
		got = nil
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	off := false
	host := "h.example.com"
	require.NoError(t, api.PatchEnvironment("a b", types.EnvUpdateRequest{DebugHTTP: &off, Hostname: &host}))
	require.Equal(t, "a b", gotEnv)
	// false is sent, not dropped; unset fields are not sent.
	require.Equal(t, map[string]interface{}{"debug_http": false, "hostname": host}, got)
	err := api.PatchEnvironment("nope", types.EnvUpdateRequest{DebugHTTP: &off})
	require.ErrorContains(t, err, "403")
	require.ErrorContains(t, err, "permission check failed")
}

func TestPatchEnvironmentIntervals(t *testing.T) {
	mux := http.NewServeMux()
	var got map[string]interface{}
	mux.HandleFunc("PATCH /api/v1/environments/intervals/{env}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("env") == "nope" {
			forbidden(w)
			return
		}
		require.Equal(t, "dev", r.PathValue("env"))
		got = nil
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{}`))
	})
	api := newRealURLServer(t, mux)
	cfg, qry := 10, 30
	require.NoError(t, api.PatchEnvironmentIntervals("dev", &cfg, nil, &qry))
	require.Equal(t, map[string]interface{}{"config_interval": float64(10), "query_interval": float64(30)}, got)
	require.ErrorContains(t, api.PatchEnvironmentIntervals("nope", &cfg, nil, nil), "403")
}

func TestSetEnrollPackageURL(t *testing.T) {
	mux := http.NewServeMux()
	var gotAction string
	var got types.ApiActionsRequest
	mux.HandleFunc("POST /api/v1/environments/{env}/enroll/{action}", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "dev", r.PathValue("env"))
		gotAction = r.PathValue("action")
		got = types.ApiActionsRequest{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	})
	api := newRealURLServer(t, mux)
	u := "https://pkg.example.com/x"
	for action, want := range map[string]types.ApiActionsRequest{
		"set_deb": {DebPkgURL: u},
		"set_rpm": {RpmPkgURL: u},
		"set_msi": {MsiPkgURL: u},
		"set_pkg": {MacPkgURL: u},
	} {
		require.NoError(t, api.SetEnrollPackageURL("dev", action, u), action)
		require.Equal(t, action, gotAction)
		require.Equal(t, want, got, action)
	}
	gotAction = ""
	require.ErrorContains(t, api.SetEnrollPackageURL("dev", "extend", u), "unknown package action")
	require.Empty(t, gotAction, "an unknown action is not sent")
}

func TestUploadCertificate(t *testing.T) {
	mux := http.NewServeMux()
	var got map[string]string
	mux.HandleFunc("POST /api/v1/environments/{env}/enroll/cert", func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "dev", r.PathValue("env"))
		got = nil
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		pem, err := base64.StdEncoding.DecodeString(got["certificate_b64"])
		require.NoError(t, err)
		if string(pem) == "bad" {
			http.Error(w, `{"error":"invalid PEM: no CERTIFICATE block"}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"message":"certificate uploaded successfully"}`))
	})
	api := newRealURLServer(t, mux)
	require.NoError(t, api.UploadCertificate("dev", "-----BEGIN CERTIFICATE-----\n"))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\n")), got["certificate_b64"])
	err := api.UploadCertificate("dev", "bad")
	require.ErrorContains(t, err, "400")
	require.ErrorContains(t, err, "invalid PEM")
}

func TestDeleteEnvironment(t *testing.T) {
	mux := http.NewServeMux()
	var gotEnv string
	mux.HandleFunc("DELETE /api/v1/environments/{env}", func(w http.ResponseWriter, r *http.Request) {
		gotEnv = r.PathValue("env")
		body, _ := io.ReadAll(r.Body)
		require.Empty(t, body)
		if gotEnv == "nope" {
			forbidden(w)
			return
		}
		_, _ = w.Write([]byte(`{"message":"environment deleted"}`))
	})
	api := newRealURLServer(t, mux)
	require.NoError(t, api.DeleteEnvironment("a/b"))
	require.Equal(t, "a/b", gotEnv, "the name is one escaped path segment")
	err := api.DeleteEnvironment("nope")
	require.ErrorContains(t, err, "403")
	require.ErrorContains(t, err, "permission check failed")
}
