package vulns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedAt(introduced, fixed string) []Range {
	return []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: introduced}, {Fixed: fixed}}}}
}

func TestIsAffected(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		version   string
		ranges    []Range
		versions  []string
		want      bool
		wantFixed string
	}{
		{"debian tilde sorts before release", "Debian:12", "1:2.3~rc1-1", fixedAt("0", "1:2.3-1"), nil, true, "1:2.3-1"},
		{"debian fixed version is not affected", "Debian:12", "1:2.3-1", fixedAt("0", "1:2.3-1"), nil, false, ""},
		{"debian missing epoch is epoch 0", "Debian:12", "2.3-1", fixedAt("0", "1:2.3-1"), nil, true, "1:2.3-1"},
		{"ubuntu revision", "Ubuntu:22.04", "3.0.2-0ubuntu1.15", fixedAt("0", "3.0.2-0ubuntu1.16"), nil, true, "3.0.2-0ubuntu1.16"},
		{"rpm with epoch", "Red Hat:9", "1:22.23.1-1.module+el9.8.0+1+abc", fixedAt("0", "1:22.23.2-2.module+el9.8.0+24958+80b2ac6e"), nil, true, "1:22.23.2-2.module+el9.8.0+24958+80b2ac6e"},
		{"rpm missing epoch is not epoch 1", "Red Hat:9", "22.23.2-2.el9", fixedAt("0", "1:22.23.2-2.el9"), nil, true, "1:22.23.2-2.el9"},
		{"rocky dist tag", "Rocky Linux:9", "1.2-3.el9_4", fixedAt("0", "1.2-3.el9_5"), nil, true, "1.2-3.el9_5"},
		{"pypi pre-release is before release", "PyPI", "2.2.1rc1", fixedAt("2.0", "2.2.1"), nil, true, "2.2.1"},
		{"pypi below introduced", "PyPI", "1.9", fixedAt("2.0", "2.2.1"), nil, false, ""},
		{"npm pre-release is before release", "npm", "4.17.21-beta.1", fixedAt("0", "4.17.21"), nil, true, "4.17.21"},
		{"last_affected is inclusive", "PyPI", "1.5", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {LastAffected: "1.5"}}}}, nil, true, ""},
		{"above last_affected", "PyPI", "1.5.1", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {LastAffected: "1.5"}}}}, nil, false, ""},
		{"unbounded introduced 0, no fix yet", "Ubuntu:22.04", "5.15.0-100.110", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}}}, nil, true, ""},
		{"explicit versions list", "Debian:12", "1.2-3", nil, []string{"1.2-2", "1.2-3"}, true, ""},
		{"second range matches", "PyPI", "3.1", append(fixedAt("1.0", "1.4"), fixedAt("3.0", "3.2")...), nil, true, "3.2"},
		{"re-introduced after a fix", "PyPI", "2.5", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {Fixed: "2.0"}, {Introduced: "2.4"}, {Fixed: "2.6"}}}}, nil, true, "2.6"},
		{"between fix and re-introduction", "PyPI", "2.1", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "1.0"}, {Fixed: "2.0"}, {Introduced: "2.4"}, {Fixed: "2.6"}}}}, nil, false, ""},
		{"git ranges are ignored", "PyPI", "1.0", []Range{{Type: "GIT", Events: []Event{{Introduced: "0"}}}}, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, fixed, err := isAffected(tt.ecosystem, tt.version, tt.ranges, tt.versions)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantFixed, fixed)
		})
	}
}

// The comparators accept anything ("garbage" parses as a version), so a
// version with no digit must be reported as unassessable, never as clean.
func TestAssessableVersion(t *testing.T) {
	for _, v := range []string{"1", "2:1.0-1", "1.0rc1"} {
		assert.True(t, assessableVersion(v), v)
	}
	for _, v := range []string{"", "unknown", "garbage", "  "} {
		assert.False(t, assessableVersion(v), v)
	}
}
