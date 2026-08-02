package filequery

import (
	"fmt"
	"path"
	"strings"
)

func DefaultRoot(platform string) string {
	if strings.EqualFold(platform, "windows") {
		return `C:\`
	}
	return "/"
}

func ResolvePath(input, current, platform string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		input = current
	}
	if strings.EqualFold(platform, "windows") {
		return resolveWindowsPath(input, current)
	}
	if strings.HasPrefix(input, "/") {
		return path.Clean(input)
	}
	return path.Clean(path.Join(current, input))
}

func ListDirectorySQL(directory string) string {
	return fmt.Sprintf("select path, filename, directory, type, size, mode, uid, gid, mtime from file where directory = %s", quoteSQL(directory))
}

func StatPathSQL(target string) string {
	return fmt.Sprintf("select path, filename, directory, type, size, mode, uid, gid, mtime, atime, ctime from file where path = %s", quoteSQL(target))
}

func resolveWindowsPath(input, current string) string {
	input = strings.ReplaceAll(input, "/", `\`)
	current = strings.ReplaceAll(current, "/", `\`)
	if isWindowsAbs(input) {
		return cleanWindowsPath(input)
	}
	return cleanWindowsPath(strings.TrimRight(current, `\`) + `\` + input)
}

func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '\\'
}

func cleanWindowsPath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	parts := []string{}
	for _, part := range strings.Split(p, `\`) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(parts) > 1 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return `C:\`
	}
	if len(parts) == 1 && strings.HasSuffix(parts[0], ":") {
		return parts[0] + `\`
	}
	return strings.Join(parts, `\`)
}

func quoteSQL(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
