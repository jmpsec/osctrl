package vulns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

// ErrTooLarge is returned when a download is bigger than the configured cap.
var ErrTooLarge = errors.New("download exceeds the size limit")

// statusError is a non-200 response.
type statusError struct {
	url  string
	code int
}

func (e statusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.url, e.code) }

// fetcher downloads feed files. Every body it returns is capped, so no
// caller can forget the limit.
type fetcher struct {
	client   *http.Client
	maxBytes int64
}

func (f fetcher) open(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "osctrl-vulns")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, statusError{url: url, code: resp.StatusCode}
	}
	if resp.ContentLength > f.maxBytes {
		_ = resp.Body.Close()
		return nil, ErrTooLarge
	}
	return &cappedBody{r: io.LimitReader(resp.Body, f.maxBytes+1), c: resp.Body, left: f.maxBytes}, nil
}

// cappedBody fails once more than maxBytes have been read, for responses
// whose Content-Length is missing or wrong.
type cappedBody struct {
	r    io.Reader
	c    io.Closer
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n, ErrTooLarge
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.c.Close() }

func (f fetcher) readAll(ctx context.Context, url string) ([]byte, error) {
	rc, err := f.open(ctx, url)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// toTemp downloads url into a temporary file. The caller closes and removes
// it. Archives need random access, and holding a 1 GiB zip in memory is not
// an option.
func (f fetcher) toTemp(ctx context.Context, url string) (*os.File, int64, error) {
	rc, err := f.open(ctx, url)
	if err != nil {
		return nil, 0, err
	}
	defer rc.Close()
	tmp, err := os.CreateTemp("", "osctrl-vuln-*.zip")
	if err != nil {
		return nil, 0, err
	}
	n, err := io.Copy(tmp, rc)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, 0, err
	}
	return tmp, n, nil
}
