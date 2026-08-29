package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestConfigVersionWarning(t *testing.T) {
	tests := []struct {
		name        string
		fileVersion int
		wantEmpty   bool
		wantSubstr  []string
	}{
		{
			name:        "current version is silent",
			fileVersion: ConfigVersion,
			wantEmpty:   true,
		},
		{
			name:        "missing version field warns",
			fileVersion: 0,
			wantSubstr:  []string{"no version field", fmt.Sprintf("'version: %d'", ConfigVersion)},
		},
		{
			name:        "older version warns about missing fields",
			fileVersion: -1,
			wantSubstr: []string{
				fmt.Sprintf("version -1 is older than supported version %d", ConfigVersion),
				"may be missing",
			},
		},
		{
			name:        "newer version warns about stale binary",
			fileVersion: ConfigVersion + 1,
			wantSubstr: []string{
				fmt.Sprintf("version %d is newer than supported version %d", ConfigVersion+1, ConfigVersion),
				"upgrade",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConfigVersionWarning(tt.fileVersion)
			if tt.wantEmpty {
				if got != "" {
					t.Fatalf("ConfigVersionWarning(%d) = %q, want empty", tt.fileVersion, got)
				}
				return
			}
			for _, want := range tt.wantSubstr {
				if !strings.Contains(got, want) {
					t.Errorf("ConfigVersionWarning(%d) = %q, want substring %q", tt.fileVersion, got, want)
				}
			}
		})
	}
}
