package version

import (
	"encoding/json"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
