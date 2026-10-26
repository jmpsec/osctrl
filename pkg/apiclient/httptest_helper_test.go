package apiclient

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

// newRealURLServer serves mux on a real loopback httptest server and returns a
// client built with CreateAPI, so Configuration.URL has a real scheme and host
// ("http://127.0.0.1:port"). Use it instead of CreateAPIWithTransport when a
// test must catch URL-building bugs: a transport that routes on the path alone
// hides a URL whose host was mangled (for example path.Join on the full URL
// turning "http://host" into "http:/host"); a real server cannot be reached
// through such a URL. The client sends "Authorization: Bearer testtoken".
func newRealURLServer(t *testing.T, mux *http.ServeMux) *OsctrlAPI {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	api, err := CreateAPI(JSONConfigurationAPI{URL: srv.URL, Token: "testtoken"}, false)
	require.NoError(t, err)
	return api
}

func TestRealURLServerKeepsHost(t *testing.T) {
	mux := http.NewServeMux()
	hits := 0
	var gotHost string
	mux.HandleFunc("GET /api/v1/environments/{env}", func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotHost = r.Host
		_, _ = w.Write([]byte(`{"name":"` + r.PathValue("env") + `"}`))
	})
	api := newRealURLServer(t, mux)

	env, err := api.GetEnvironment("dev")
	require.NoError(t, err)
	require.Equal(t, "dev", env.Name)
	require.Equal(t, api.Configuration.URL, "http://"+gotHost)

	// path.Join on the full URL collapses "http://" to "http:/" and drops the
	// host: the helper must make that bug fail, not reach the handler.
	_, err = api.GetGeneric(path.Join(api.Configuration.URL, APIPath, APIEnvironments, "dev"), nil)
	require.Error(t, err)
	require.Equal(t, 1, hits)
}
