package version

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestVersionConstantsAreValid(t *testing.T) {
	semverPattern := regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	assert.Regexp(t, semverPattern, OsctrlVersion)
	assert.Regexp(t, semverPattern, OsqueryVersion)
}

func TestVersionDataURL(t *testing.T) {
	parsedURL, err := url.ParseRequestURI(VersionDataURL)

	assert.NoError(t, err)
	assert.Equal(t, "https", parsedURL.Scheme)
	assert.Equal(t, "stats.osctrl.net", parsedURL.Host)
	assert.Equal(t, "/version_data.json", parsedURL.Path)
}

func TestVersionDataJSONTags(t *testing.T) {
	data := VersionData{
		OsqueryVersion:   "5.21.0",
		LatestRelease:    "0.5.1",
		SuggestedRelease: "0.5.1",
		MoreInformation:  "https://docs.example.com/releases/0.5.1",
	}

	encoded, err := json.Marshal(data)
	assert.NoError(t, err)

	var decoded map[string]string
	err = json.Unmarshal(encoded, &decoded)
	assert.NoError(t, err)

	assert.Equal(t, data.OsqueryVersion, decoded["osqueryVersion"])
	assert.Equal(t, data.LatestRelease, decoded["latestRelease"])
	assert.Equal(t, data.SuggestedRelease, decoded["suggestedRelease"])
	assert.Equal(t, data.MoreInformation, decoded["moreInformation"])
}

func TestRetrieveVersionDataSuccess(t *testing.T) {
	previousClient := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previousClient })

	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, VersionDataURL, req.URL.String())
			assert.NotNil(t, req.Context())

			payload := `{"latestRelease":"0.5.1","osqueryVersion":"5.21.0","suggestedRelease":"0.5.1","moreInformation":"https://docs.example.com/releases/0.5.1"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(payload)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	data, err := RetrieveVersionData(VersionDataURL)
	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, "0.5.1", data.LatestRelease)
	assert.Equal(t, "5.21.0", data.OsqueryVersion)
	assert.Equal(t, "0.5.1", data.SuggestedRelease)
	assert.Equal(t, "https://docs.example.com/releases/0.5.1", data.MoreInformation)
}

func TestRetrieveVersionDataUnexpectedStatus(t *testing.T) {
	previousClient := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previousClient })

	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadGateway,
				Body:       io.NopCloser(strings.NewReader("bad gateway")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	data, err := RetrieveVersionData(VersionDataURL)
	assert.Nil(t, data)
	assert.EqualError(t, err, "unexpected status code: 502")
}

func TestRetrieveVersionDataInvalidJSON(t *testing.T) {
	previousClient := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = previousClient })

	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("{")),
				Header:     make(http.Header),
			}, nil
		}),
	}

	data, err := RetrieveVersionData(VersionDataURL)
	assert.Nil(t, data)
	assert.Error(t, err)
}
