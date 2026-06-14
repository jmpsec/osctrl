package discovery

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	internaltransport "github.com/jmpsec/osctrl/tools/fake_news_go/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDiscoverResolvesOnlyEnvironmentsWithSecrets(t *testing.T) {
	t.Parallel()

	client := NewClient("https://api.example.test", internaltransport.New(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/v1/login":
			return jsonResponse(http.StatusOK, `{"token":"jwt-token"}`), nil
		case "/api/v1/environments":
			if got := req.Header.Get("Authorization"); got != "Bearer jwt-token" {
				t.Fatalf("expected bearer token, got %q", got)
			}
			return jsonResponse(http.StatusOK, `[
				{"uuid":"env-b","name":"Bravo"},
				{"uuid":"env-a","name":"Alpha"}
			]`), nil
		case "/api/v1/environments/env-a/enroll/secret":
			return jsonResponse(http.StatusOK, `{"data":"secret-a"}`), nil
		case "/api/v1/environments/env-b/enroll/secret":
			return jsonResponse(http.StatusForbidden, `{"error":"no access"}`), nil
		default:
			t.Fatalf("unexpected request path %s", req.URL.Path)
			return nil, nil
		}
	})))

	envs, err := client.Discover(context.Background(), "admin", "secret")
	if err != nil {
		t.Fatalf("unexpected discovery error: %v", err)
	}
	if len(envs) != 1 {
		t.Fatalf("expected one discoverable environment, got %d", len(envs))
	}
	if envs[0].UUID != "env-a" {
		t.Fatalf("expected env-a, got %q", envs[0].UUID)
	}
	if envs[0].Secret != "secret-a" {
		t.Fatalf("expected secret-a, got %q", envs[0].Secret)
	}
}

func TestDiscoverFailsWhenNoSecretsAreAccessible(t *testing.T) {
	t.Parallel()

	client := NewClient("https://api.example.test", internaltransport.New(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/api/v1/login":
			return jsonResponse(http.StatusOK, `{"token":"jwt-token"}`), nil
		case "/api/v1/environments":
			return jsonResponse(http.StatusOK, `[{"uuid":"env-a","name":"Alpha"}]`), nil
		case "/api/v1/environments/env-a/enroll/secret":
			return jsonResponse(http.StatusForbidden, `{"error":"no access"}`), nil
		default:
			t.Fatalf("unexpected request path %s", req.URL.Path)
			return nil, nil
		}
	})))

	_, err := client.Discover(context.Background(), "admin", "secret")
	if err == nil {
		t.Fatal("expected discovery error")
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
