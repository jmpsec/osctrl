package vulns

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// cpe.go — matching installed applications to NVD CPE names. It is exact
// lookups and a numeric version comparison, nothing fuzzier: results are
// "possible" findings because names are only a hint.

// cpeEcosystem is the Affected.Ecosystem of NVD rows and the Finding.Ecosystem
// of the possible findings they produce.
const cpeEcosystem = "cpe"

// cpeCategories are matched only through NVD CPE data.
var cpeCategories = map[string]bool{
	CategoryHomebrew: true, CategoryPrograms: true, CategoryApps: true, CategoryChocolatey: true,
}

// cpeName is the part of a CPE 2.3 name matching uses.
type cpeName struct{ Part, Vendor, Product, Version string }

// parseCPE splits a CPE 2.3 formatted string ("cpe:2.3:a:vendor:product:
// version:..."). Backslash escapes are honored and removed, so
// "notepad\+\+" is "notepad++" and "\:" is not a separator.
func parseCPE(s string) (cpeName, bool) {
	rest, ok := strings.CutPrefix(s, "cpe:2.3:")
	if !ok {
		return cpeName{}, false
	}
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range rest {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	fields = append(fields, cur.String())
	if len(fields) < 4 {
		return cpeName{}, false
	}
	n := cpeName{Part: fields[0], Vendor: strings.ToLower(fields[1]), Product: strings.ToLower(fields[2]), Version: fields[3]}
	if n.Vendor == "" || n.Vendor == "*" || n.Product == "" || n.Product == "*" {
		return cpeName{}, false
	}
	return n, true
}

// cpeRange is one NVD cpeMatch version window, stored as NVD states it: OSV
// range events cannot express versionStartExcluding. No bound at all means
// every version.
type cpeRange struct {
	StartIncluding string `json:"start_including,omitempty"`
	StartExcluding string `json:"start_excluding,omitempty"`
	EndIncluding   string `json:"end_including,omitempty"`
	EndExcluding   string `json:"end_excluding,omitempty"`
}

// cpeAffected compares version against an NVD product's exact versions and
// ranges. fixed is the excluded end of the matching range, when there is one.
func cpeAffected(version string, ranges []cpeRange, versions []string) (bool, string, error) {
	v, ok := dottedVersion(version)
	if !ok {
		return false, "", ErrUnassessable
	}
	for _, exact := range versions {
		if e, ok := dottedVersion(exact); ok && compareDotted(v, e) == 0 {
			return true, "", nil
		}
	}
	for _, r := range ranges {
		in, err := r.contains(v)
		if err != nil {
			return false, "", err
		}
		if in {
			return true, r.EndExcluding, nil
		}
	}
	return false, "", nil
}

func (r cpeRange) contains(v []string) (bool, error) {
	bounds := []struct {
		raw string
		ok  func(c int) bool
	}{
		{r.StartIncluding, func(c int) bool { return c >= 0 }},
		{r.StartExcluding, func(c int) bool { return c > 0 }},
		{r.EndIncluding, func(c int) bool { return c <= 0 }},
		{r.EndExcluding, func(c int) bool { return c < 0 }},
	}
	for _, b := range bounds {
		if b.raw == "" {
			continue
		}
		bv, ok := dottedVersion(b.raw)
		if !ok {
			return false, fmt.Errorf("%w: bound %q", ErrUnassessable, b.raw)
		}
		if !b.ok(compareDotted(v, bv)) {
			return false, nil
		}
	}
	return true, nil
}

// dottedVersion is the leading dotted-numeric run of v as digit strings
// without leading zeros (zero is ""): "128.0.3 (64-bit)" is [128 "" 3],
// "v2.10" is [2 10]. ok is false when v has no digit.
func dottedVersion(v string) ([]string, bool) {
	i := strings.IndexFunc(v, func(r rune) bool { return r >= '0' && r <= '9' })
	if i < 0 {
		return nil, false
	}
	var parts []string
	for _, seg := range strings.Split(v[i:], ".") {
		end := 0
		for end < len(seg) && seg[end] >= '0' && seg[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		parts = append(parts, strings.TrimLeft(seg[:end], "0"))
		if end < len(seg) {
			break // "3-beta" ends the run
		}
	}
	return parts, true
}

// compareDotted orders dotted versions numerically, part by part; a missing
// part is 0. Parts are compared as digit strings, so no size overflows.
func compareDotted(a, b []string) int {
	for i := range max(len(a), len(b)) {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmp.Compare(len(x), len(y)); c != 0 {
			return c
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	return 0
}

var (
	cpeBracketed    = regexp.MustCompile(`\([^)]*\)|\[[^\]]*\]`)
	cpeVersionToken = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
	cpeDisallowed   = regexp.MustCompile(`[^a-z0-9._+\-]`)
	cpeArchTokens   = map[string]bool{
		"x64": true, "x86": true, "x86_64": true, "amd64": true, "arm64": true, "aarch64": true,
		"64-bit": true, "32-bit": true, "64bit": true, "32bit": true, "win64": true, "win32": true,
	}
	cpeCorporateTokens = map[string]bool{
		"inc": true, "incorporated": true, "corp": true, "corporation": true, "co": true, "company": true,
		"ltd": true, "limited": true, "llc": true, "gmbh": true, "ag": true, "sa": true, "bv": true, "srl": true, "plc": true,
	}
)

// cpeTokens lowercases s, drops bracketed text ("(x64 en-US)"), and splits
// it into words without the characters CPE names never contain.
func cpeTokens(s string) []string {
	s = cpeBracketed.ReplaceAllString(strings.ToLower(s), " ")
	var out []string
	for _, f := range strings.Fields(s) {
		if f = strings.Trim(cpeDisallowed.ReplaceAllString(f, ""), "._-"); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// cpeProductName is a display name in CPE spelling, without version and
// architecture words: "7-Zip 23.01 (x64)" is "7-zip".
func cpeProductName(name string) string {
	var keep []string
	for _, tok := range cpeTokens(name) {
		if !cpeArchTokens[tok] && !cpeVersionToken.MatchString(tok) {
			keep = append(keep, tok)
		}
	}
	return strings.Join(keep, "_")
}

// cpeVendorNames turns a publisher into vendor candidates: the name without
// corporate suffixes, and its first word ("Oracle America, Inc." gives
// oracle_america and oracle).
func cpeVendorNames(vendor string) []string {
	var keep []string
	for _, tok := range cpeTokens(vendor) {
		if !cpeCorporateTokens[tok] {
			keep = append(keep, tok)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	out := []string{strings.Join(keep, "_")}
	first := keep[0]
	if first == "the" && len(keep) > 1 {
		first = keep[1]
	}
	if first != out[0] {
		out = append(out, first)
	}
	return out
}

// cpeCandidates returns the vendor and product names a package may be listed
// under in NVD. Windows programs carry a publisher, macOS apps a reverse-DNS
// bundle id; Homebrew and Chocolatey packages carry no vendor.
func cpeCandidates(sw NodeSoftware) (vendors, products []string) {
	name := sw.Name
	switch sw.Category {
	case CategoryPrograms:
		vendors = cpeVendorNames(sw.Vendor)
	case CategoryApps:
		// org.mozilla.firefox → mozilla
		if labels := strings.Split(strings.ToLower(sw.Vendor), "."); len(labels) >= 2 && labels[1] != "" {
			vendors = []string{labels[1]}
		}
	case CategoryHomebrew:
		name, _, _ = strings.Cut(name, "@") // openssl@3 → openssl
	}
	product := cpeProductName(name)
	if product == "" {
		return vendors, nil
	}
	products = []string{product}
	// "Mozilla Firefox" by Mozilla is mozilla:firefox, not mozilla:mozilla_firefox.
	for _, v := range vendors {
		if rest, ok := strings.CutPrefix(product, v+"_"); ok && rest != "" && !slices.Contains(products, rest) {
			products = append(products, rest)
		}
	}
	return vendors, products
}

// resolveCPE returns the vendor:product keys a package is listed under.
// byProduct maps each candidate product to the vendors stored CVEs list it
// for; known marks the candidate vendors that are CPE vendors at all. A
// matching vendor candidate decides. Otherwise a product is taken only when
// a single vendor ships it, the package has no known vendor to contradict
// that (Apple's Terminal is not another vendor's "terminal"), and the name
// is the package's own rather than one stripped of its vendor ("Docker
// Desktop" → desktop), which is too generic. Nothing is guessed beyond that.
func resolveCPE(vendors, products []string, byProduct map[string][]string, known map[string]bool) []string {
	knownVendor := slices.ContainsFunc(vendors, func(v string) bool { return known[v] })
	var keys []string
	for i, p := range products {
		listed := byProduct[p]
		matched := false
		for _, v := range vendors {
			if slices.Contains(listed, v) {
				keys = append(keys, v+":"+p)
				matched = true
			}
		}
		if !matched && i == 0 && !knownVendor && len(listed) == 1 {
			keys = append(keys, listed[0]+":"+p)
		}
	}
	return keys
}
