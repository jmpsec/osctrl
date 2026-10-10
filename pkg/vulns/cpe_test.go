package vulns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCPE(t *testing.T) {
	n, ok := parseCPE("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*")
	require.True(t, ok)
	assert.Equal(t, cpeName{Part: "a", Vendor: "mozilla", Product: "firefox", Version: "*"}, n)

	n, ok = parseCPE(`cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6:*:*:*:*:*:*:*`)
	require.True(t, ok)
	assert.Equal(t, "notepad++", n.Product, "escapes are removed")
	assert.Equal(t, "8.6", n.Version)

	n, ok = parseCPE(`cpe:2.3:a:acme:tool\:pro:1.0:*:*:*:*:*:*:*`)
	require.True(t, ok)
	assert.Equal(t, "tool:pro", n.Product, "an escaped colon is not a separator")

	n, ok = parseCPE("cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*")
	require.True(t, ok)
	assert.Equal(t, "o", n.Part)

	for _, bad := range []string{"", "cpe:/a:mozilla:firefox", "cpe:2.3:a", "cpe:2.3:a:*:firefox:1:*:*:*:*:*:*:*", "cpe:2.3:a:mozilla:*:1:*:*:*:*:*:*:*"} {
		_, ok := parseCPE(bad)
		assert.False(t, ok, bad)
	}
}

func TestCompareDotted(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"128.0.3", "130.0", -1},
		{"1.2", "1.2.0", 0},
		{"2.10", "2.9", 1},
		{"1.2.3-beta", "1.2.3", 0},
		{"v1.2", "1.2", 0},
		{"128.0.3 (64-bit)", "128.0.3", 0},
		{"12345678901234567890", "9", 1},
		{"01.2", "1.2", 0},
	}
	for _, tt := range tests {
		a, okA := dottedVersion(tt.a)
		b, okB := dottedVersion(tt.b)
		require.True(t, okA && okB, "%s / %s", tt.a, tt.b)
		assert.Equal(t, tt.want, compareDotted(a, b), "%s vs %s", tt.a, tt.b)
	}
	_, ok := dottedVersion("dev")
	assert.False(t, ok, "no digit, no version")
}

func TestCPEAffected(t *testing.T) {
	below130 := []cpeRange{{EndExcluding: "130.0"}}
	hit, fixed, err := cpeAffected("128.0.3", below130, nil)
	require.NoError(t, err)
	assert.True(t, hit)
	assert.Equal(t, "130.0", fixed)

	hit, _, _ = cpeAffected("130.0", below130, nil)
	assert.False(t, hit, "the excluded end is the fix")

	hit, fixed, _ = cpeAffected("5.0", []cpeRange{{StartIncluding: "5.0", EndIncluding: "5.2"}}, nil)
	assert.True(t, hit)
	assert.Empty(t, fixed, "an included end names no fix")

	hit, _, _ = cpeAffected("5.0", []cpeRange{{StartExcluding: "5.0", EndIncluding: "5.2"}}, nil)
	assert.False(t, hit)

	hit, _, _ = cpeAffected("8.6", nil, []string{"8.6"})
	assert.True(t, hit, "an exact version")

	hit, _, _ = cpeAffected("1.0", []cpeRange{{}}, nil)
	assert.True(t, hit, "no bound at all means every version")

	_, _, err = cpeAffected("unknown", below130, nil)
	assert.ErrorIs(t, err, ErrUnassessable)
	_, _, err = cpeAffected("1.0", []cpeRange{{EndExcluding: "next"}}, nil)
	assert.ErrorIs(t, err, ErrUnassessable)
}

func TestCPECandidates(t *testing.T) {
	tests := []struct {
		sw                NodeSoftware
		vendors, products []string
	}{
		{NodeSoftware{Category: CategoryPrograms, Name: "Mozilla Firefox (x64 en-US)", Vendor: "Mozilla"},
			[]string{"mozilla"}, []string{"mozilla_firefox", "firefox"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "7-Zip 23.01 (x64)", Vendor: "Igor Pavlov"},
			[]string{"igor_pavlov", "igor"}, []string{"7-zip"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "Microsoft Visual Studio Code (User)", Vendor: "Microsoft Corporation"},
			[]string{"microsoft"}, []string{"microsoft_visual_studio_code", "visual_studio_code"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "Notepad++ (64-bit x64)", Vendor: "Notepad++ Team"},
			[]string{"notepad++_team", "notepad++"}, []string{"notepad++"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "Python 3.12.1 (64-bit)", Vendor: "Python Software Foundation"},
			[]string{"python_software_foundation", "python"}, []string{"python"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "Java 8", Vendor: "Oracle America, Inc."},
			[]string{"oracle_america", "oracle"}, []string{"java"}},
		{NodeSoftware{Category: CategoryApps, Name: "Google Chrome", Vendor: "com.google.Chrome"},
			[]string{"google"}, []string{"google_chrome", "chrome"}},
		{NodeSoftware{Category: CategoryHomebrew, Name: "openssl@3"}, nil, []string{"openssl"}},
		{NodeSoftware{Category: CategoryChocolatey, Name: "googlechrome"}, nil, []string{"googlechrome"}},
		{NodeSoftware{Category: CategoryPrograms, Name: "", Vendor: "Acme"}, []string{"acme"}, nil},
	}
	for _, tt := range tests {
		vendors, products := cpeCandidates(tt.sw)
		assert.Equal(t, tt.vendors, vendors, "vendors of %q", tt.sw.Name)
		assert.Equal(t, tt.products, products, "products of %q", tt.sw.Name)
	}
}

func TestResolveCPE(t *testing.T) {
	byProduct := map[string][]string{
		"firefox":  {"mozilla"},
		"7-zip":    {"7-zip"},
		"jq":       {"jqlang", "stedolan"},
		"terminal": {"acme"},
		"desktop":  {"acme"},
	}
	known := map[string]bool{"mozilla": true, "7-zip": true, "jqlang": true, "stedolan": true, "acme": true, "apple": true, "docker": true}
	assert.Equal(t, []string{"mozilla:firefox"}, resolveCPE([]string{"mozilla"}, []string{"mozilla_firefox", "firefox"}, byProduct, known))
	assert.Equal(t, []string{"7-zip:7-zip"}, resolveCPE([]string{"igor_pavlov", "igor"}, []string{"7-zip"}, byProduct, known), "one vendor ships it")
	assert.Empty(t, resolveCPE(nil, []string{"jq"}, byProduct, known), "two vendors ship jq: no guessing")
	assert.Equal(t, []string{"jqlang:jq"}, resolveCPE([]string{"jqlang"}, []string{"jq"}, byProduct, known))
	assert.Empty(t, resolveCPE(nil, []string{"unlisted"}, byProduct, known))
	// A known vendor that does not list the product contradicts the fallback:
	// Apple's Terminal is not acme's.
	assert.Empty(t, resolveCPE([]string{"apple"}, []string{"terminal"}, byProduct, known))
	// A name stripped of its vendor ("Docker Desktop" → desktop) is too
	// generic to take on another vendor's word.
	assert.Empty(t, resolveCPE([]string{"docker_inc"}, []string{"docker_desktop", "desktop"}, byProduct, known))
}
