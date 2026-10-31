package config

import (
	"fmt"
	"strings"
)

// NormalizeBasePath validates the public URL prefix the SPA and API are served
// under (for example "/osctrl") and returns it with a leading slash and no
// trailing slash. "" and "/" mean the root and return "". The value ends up in
// cookie Path attributes and Location headers, so only plain path segments are
// accepted.
func NormalizeBasePath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return "", nil
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("invalid base path %q: empty, '.' or '..' segment", p)
		}
		for _, c := range seg {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			default:
				return "", fmt.Errorf("invalid base path %q: character %q not allowed", p, c)
			}
		}
	}
	return "/" + p, nil
}
