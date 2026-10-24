package osqueryversions

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	versionRe = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){1,3}$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidVersion reports whether v is a 2 to 4 part numeric version with parts of
// at most 6 digits (so at most 27 characters, within the size-32 column).
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// Compare returns -1, 0 or 1 comparing versions part by part; a missing part
// counts as 0. It errors when either version is invalid.
func Compare(a, b string) (int, error) {
	if !ValidVersion(a) || !ValidVersion(b) {
		return 0, fmt.Errorf("invalid version: %q or %q", a, b)
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, err := part(pa, i)
		if err != nil {
			return 0, err
		}
		y, err := part(pb, i)
		if err != nil {
			return 0, err
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func part(p []string, i int) (int, error) {
	if i >= len(p) {
		return 0, nil
	}
	return strconv.Atoi(p[i])
}

// supported maps platform and format to the arches the library accepts.
var supported = map[string]map[string][]string{
	"linux":  {"deb": {"amd64", "arm64"}, "rpm": {"amd64", "arm64"}},
	"darwin": {"pkg": {"universal"}},
	// Windows hosts get the target only: no rollback digest is needed. amd64
	// only: osctrld has no verified ARM64 MSI asset yet.
	"windows": {"msi": {"amd64"}},
}

// ValidEntry checks that the platform, arch and format are a supported
// combination and that sha256 is 64 lowercase hex characters.
func ValidEntry(platform, arch, format, sha256 string) error {
	arches, ok := supported[platform][format]
	if !ok {
		return fmt.Errorf("unsupported platform/format: %q/%q", platform, format)
	}
	found := false
	for _, a := range arches {
		found = found || a == arch
	}
	if !found {
		return fmt.Errorf("unsupported arch %q for %s/%s", arch, platform, format)
	}
	if !sha256Re.MatchString(sha256) {
		return fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// unsupportedNodePlatforms are stored node platforms (osquery's platform
// column, which holds distro names such as ubuntu, so the library's
// platform table does not apply to it) for which the library has no package: osctrld cannot
// upgrade these hosts. ponytail: deny-list, extend when another is reported.
var unsupportedNodePlatforms = []string{"freebsd"}

// NodePlatformSupported is the one rule for whether a stored node platform is
// part of upgrades, shared by thresholds, progress, the behind gauge and the
// node API. Windows is supported; an empty or unknown platform keeps counting
// (it is unsupported only if listed above), case-insensitive.
func NodePlatformSupported(platform string) bool {
	p := strings.ToLower(platform)
	for _, u := range unsupportedNodePlatforms {
		if p == u {
			return false
		}
	}
	return true
}

// SupportedNodePlatformSQL is NodePlatformSupported as a WHERE fragment on the
// given platform column, for the raw queries of packages that cannot be
// imported here.
func SupportedNodePlatformSQL(column string) string {
	return "LOWER(COALESCE(" + column + ", '')) NOT IN ('" + strings.Join(unsupportedNodePlatforms, "','") + "')"
}
