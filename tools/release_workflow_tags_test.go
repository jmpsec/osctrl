package tools

import (
	"bufio"
	"os"
	"path"
	"strings"
	"testing"
)

func TestReleaseWorkflowAcceptsBareSemverPrereleaseTags(t *testing.T) {
	patterns, err := releaseWorkflowTagPatterns()
	if err != nil {
		t.Fatal(err)
	}

	if !matchesAny(patterns, "1.2.3-test") {
		t.Fatalf("release workflow tags %v do not match bare semver prerelease tag", patterns)
	}
}

func releaseWorkflowTagPatterns() ([]string, error) {
	f, err := os.Open("../.github/workflows/release.yml")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	inTags := false
	tagsIndent := -1
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "tags:" {
			inTags = true
			tagsIndent = len(line) - len(strings.TrimLeft(line, " "))
			continue
		}
		if !inTags {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed != "" && indent <= tagsIndent {
			break
		}
		if pattern, ok := strings.CutPrefix(trimmed, "- "); ok {
			patterns = append(patterns, strings.Trim(pattern, `"'`))
		}
	}
	return patterns, scanner.Err()
}

func matchesAny(patterns []string, tag string) bool {
	for _, pattern := range patterns {
		if ok, _ := path.Match(pattern, tag); ok {
			return true
		}
	}
	return false
}
