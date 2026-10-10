package vulns

import (
	"regexp"
	"strings"
)

// Inventory categories: the suffix of each osctrl:vuln: scheduled query.
const (
	CategoryOS     = "os"
	CategoryDeb    = "deb"
	CategoryRPM    = "rpm"
	CategoryPython = "python"
	CategoryNPM    = "npm"
)

var (
	releasePrefix = regexp.MustCompile(`^(\d+\.\d+)`)
	releaseExact  = regexp.MustCompile(`^\d+\.\d+$`)
	redHatStream  = regexp.MustCompile(`^Red Hat:enterprise_linux:(\d+)::`)
	pypiSeparator = regexp.MustCompile(`[-_.]+`)
)

// platformDirs maps os_version.platform to the OSV bucket directory that
// holds that distribution's advisories.
var platformDirs = map[string]string{
	"debian":    "Debian",
	"ubuntu":    "Ubuntu",
	"rhel":      "Red Hat",
	"rocky":     "Rocky Linux",
	"almalinux": "AlmaLinux",
}

// categoryDirs maps language-package categories to their OSV directory.
var categoryDirs = map[string]string{
	CategoryPython: "PyPI",
	CategoryNPM:    "npm",
}

// OSKey returns the ecosystem key for a node's distro packages, in the form
// AdvisoryKey produces ("Debian:12", "Ubuntu:22.04", "Red Hat:9"), or "" when
// the OS is not one osctrl can assess. Inputs are os_version columns.
func OSKey(platform, version, major string) string {
	dir, ok := platformDirs[strings.ToLower(platform)]
	if !ok {
		return ""
	}
	if dir == "Ubuntu" {
		m := releasePrefix.FindStringSubmatch(version)
		if m == nil {
			return ""
		}
		return dir + ":" + m[1]
	}
	if major == "" {
		return ""
	}
	return dir + ":" + major
}

// ecosystemFor returns the ecosystem a package of category is matched in on
// a node whose OS key is osKey, or "" when it cannot be assessed.
func ecosystemFor(category, osKey string) string {
	dir, _, _ := strings.Cut(osKey, ":")
	switch category {
	case CategoryDeb:
		if dir == "Debian" || dir == "Ubuntu" {
			return osKey
		}
	case CategoryRPM:
		if dir == "Red Hat" || dir == "Rocky Linux" || dir == "AlmaLinux" {
			return osKey
		}
	default:
		return categoryDirs[category]
	}
	return ""
}

// AdvisoryKey normalizes an OSV affected[].package.ecosystem value to the key
// node packages are matched under, or "" for ecosystems osctrl does not
// match. Ubuntu Pro/FIPS and Red Hat EUS streams ship packages a standard
// install does not have, so matching them would only produce noise.
func AdvisoryKey(osvEcosystem string) string {
	parts := strings.Split(osvEcosystem, ":")
	switch parts[0] {
	case "Debian", "Rocky Linux", "AlmaLinux":
		if len(parts) == 2 && parts[1] != "" {
			return osvEcosystem
		}
	case "Ubuntu":
		if (len(parts) == 2 || (len(parts) == 3 && parts[2] == "LTS")) && releaseExact.MatchString(parts[1]) {
			return "Ubuntu:" + parts[1]
		}
	case "Red Hat":
		if m := redHatStream.FindStringSubmatch(osvEcosystem); m != nil {
			return "Red Hat:" + m[1]
		}
	case "PyPI", "npm":
		if len(parts) == 1 {
			return osvEcosystem
		}
	}
	return ""
}

// PackageKey is the identity of a package name within an ecosystem. PyPI
// names are normalized per PEP 503; everything else compares exactly.
func PackageKey(ecosystem, name string) string {
	if ecosystem == "PyPI" {
		return pypiSeparator.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}
