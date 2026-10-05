package apiclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserAgent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(UserAgent)
	}))
	defer srv.Close()

	api, err := CreateAPI(JSONConfigurationAPI{URL: srv.URL, Token: "t"}, false)
	if err != nil {
		t.Fatalf("CreateAPI: %v", err)
	}
	if _, err := api.GetGeneric(srv.URL, nil); err != nil {
		t.Fatalf("GetGeneric: %v", err)
	}
	if !strings.HasPrefix(got, "osctrl-cli-http-client/") {
		t.Fatalf("default user agent = %q, want the osctrl-cli one", got)
	}

	api.UserAgent = "osctrl-mcp/1.2.3"
	if _, err := api.GetGeneric(srv.URL, nil); err != nil {
		t.Fatalf("GetGeneric: %v", err)
	}
	if got != "osctrl-mcp/1.2.3" {
		t.Fatalf("user agent = %q, want the override", got)
	}
}
