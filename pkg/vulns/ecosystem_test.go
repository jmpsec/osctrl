package vulns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateCreatesEveryTable(t *testing.T) {
	db := newTestDB(t)
	for _, table := range []string{"node_software", "vuln_node_state", "vuln_advisories", "vuln_aliases",
		"vuln_affected", "vuln_kev", "vuln_findings", "vuln_sync_state", "vuln_worker_state"} {
		require.True(t, db.Migrator().HasTable(table), table)
	}
}

func TestOSKey(t *testing.T) {
	tests := []struct{ platform, version, major, want string }{
		{"debian", "12 (bookworm)", "12", "Debian:12"},
		{"ubuntu", "22.04.4 LTS (Jammy Jellyfish)", "22", "Ubuntu:22.04"},
		{"ubuntu", "24.10 (Oracular Oriole)", "24", "Ubuntu:24.10"},
		{"rhel", "9.4 (Plow)", "9", "Red Hat:9"},
		{"rocky", "9.4 (Blue Onyx)", "9", "Rocky Linux:9"},
		{"almalinux", "9.4 (Seafoam Ocelot)", "9", "AlmaLinux:9"},
		{"centos", "7", "7", ""},
		{"darwin", "15.1", "15", ""},
		{"debian", "", "", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, OSKey(tt.platform, tt.version, tt.major), "%+v", tt)
	}
}

func TestEcosystemFor(t *testing.T) {
	assert.Equal(t, "Debian:12", ecosystemFor(CategoryDeb, "Debian:12"))
	assert.Equal(t, "Ubuntu:22.04", ecosystemFor(CategoryDeb, "Ubuntu:22.04"))
	assert.Equal(t, "Red Hat:9", ecosystemFor(CategoryRPM, "Red Hat:9"))
	assert.Equal(t, "", ecosystemFor(CategoryRPM, "Debian:12"), "an rpm on a Debian host is not assessable")
	assert.Equal(t, "", ecosystemFor(CategoryDeb, ""), "distro packages need the OS")
	assert.Equal(t, "PyPI", ecosystemFor(CategoryPython, ""))
	assert.Equal(t, "npm", ecosystemFor(CategoryNPM, "Debian:12"))
	assert.Equal(t, "", ecosystemFor("programs", "Debian:12"))
}

func TestAdvisoryKey(t *testing.T) {
	tests := map[string]string{
		"Debian:12":                             "Debian:12",
		"Ubuntu:22.04:LTS":                      "Ubuntu:22.04",
		"Ubuntu:24.10":                          "Ubuntu:24.10",
		"Ubuntu:Pro:22.04:LTS":                  "",
		"Ubuntu:Pro:FIPS:22.04:LTS":             "",
		"Red Hat:enterprise_linux:9::appstream": "Red Hat:9",
		"Red Hat:enterprise_linux:8::baseos":    "Red Hat:8",
		"Red Hat:rhel_eus:9.2::baseos":          "",
		"Rocky Linux:9":                         "Rocky Linux:9",
		"AlmaLinux:9":                           "AlmaLinux:9",
		"PyPI":                                  "PyPI",
		"npm":                                   "npm",
		"Alpine:v3.20":                          "",
		"Debian":                                "",
		"Go":                                    "",
	}
	for in, want := range tests {
		assert.Equal(t, want, AdvisoryKey(in), in)
	}
}

func TestPackageKeyNormalizesPyPINamesOnly(t *testing.T) {
	assert.Equal(t, "django-rest-framework", PackageKey("PyPI", "Django_REST.framework"))
	assert.Equal(t, "Jinja2", PackageKey("Debian:12", "Jinja2"), "distro names are compared exactly")
	assert.Equal(t, "@babel/core", PackageKey("npm", "@babel/core"))
}
