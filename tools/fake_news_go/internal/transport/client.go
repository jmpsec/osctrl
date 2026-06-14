package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type JSONResponse struct {
	StatusCode int
	Body       map[string]interface{}
	RawBody    []byte
}

type Client struct {
	doer Doer
}

func New(doer Doer) *Client {
	if doer == nil {
		doer = http.DefaultClient
	}

	return &Client{doer: doer}
}

func NewDefault(insecure bool) *Client {
	return New(&http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		Timeout: 30 * time.Second,
	})
}

func NewJSONClient(doer Doer, _ bool) *Client {
	return New(doer)
}

func (c *Client) PostJSON(ctx context.Context, url string, payload interface{}, headers map[string]string) (JSONResponse, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return JSONResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return JSONResponse{}, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return c.doJSON(req)
}

func (c *Client) GetJSON(ctx context.Context, url string, headers map[string]string) (JSONResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return JSONResponse{}, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return c.doJSON(req)
}

func (c *Client) doJSON(req *http.Request) (JSONResponse, error) {
	resp, err := c.doer.Do(req)
	if err != nil {
		return JSONResponse{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return JSONResponse{StatusCode: resp.StatusCode}, err
	}

	out := JSONResponse{
		StatusCode: resp.StatusCode,
		Body:       make(map[string]interface{}),
		RawBody:    body,
	}
	if len(body) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(body, &out.Body); err != nil {
		var ignore interface{}
		if err := json.Unmarshal(body, &ignore); err != nil {
			return out, err
		}
	}

	return out, nil
}

func DecodeJSON[T any](body []byte, target *T) error {
	if len(body) == 0 {
		return io.EOF
	}
	return json.Unmarshal(body, target)
}
