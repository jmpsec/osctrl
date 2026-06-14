package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestJSONClientPostJSONNormalizesBody(t *testing.T) {
	t.Parallel()

	client := NewJSONClient(doFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("expected application/json content type, got %q", got)
		}

		var body map[string]string
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body["hello"] != "world" {
			t.Fatalf("unexpected request body: %+v", body)
		}

		return jsonResponse(http.StatusOK, `{"node_key":"abc"}`), nil
	}), false)

	resp, err := client.PostJSON(context.Background(), "https://example.test", map[string]string{"hello": "world"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Body["node_key"] != "abc" {
		t.Fatalf("expected node_key abc, got %+v", resp.Body)
	}
}

func TestJSONClientPostJSONAppliesHeadersAndPreservesNon200Body(t *testing.T) {
	t.Parallel()

	client := NewJSONClient(doFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("X-Test-Header"); got != "value" {
			t.Fatalf("expected custom header to be set, got %q", got)
		}
		return jsonResponse(http.StatusUnauthorized, `{"error":"denied"}`), nil
	}), false)

	resp, err := client.PostJSON(
		context.Background(),
		"https://example.test",
		map[string]string{"hello": "world"},
		map[string]string{"X-Test-Header": "value"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.StatusCode)
	}
	if resp.Body["error"] != "denied" {
		t.Fatalf("expected error body to be decoded, got %+v", resp.Body)
	}
}

func TestJSONClientGetJSONAllowsArrayPayloads(t *testing.T) {
	t.Parallel()

	client := NewJSONClient(doFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		return jsonResponse(http.StatusOK, `[{"uuid":"env-1"}]`), nil
	}), false)

	resp, err := client.GetJSON(context.Background(), "https://example.test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if len(resp.RawBody) == 0 {
		t.Fatal("expected raw body to be preserved")
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
