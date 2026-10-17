package nodeconfig

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Merge deep-merges override on top of envConfig and returns the indented JSON.
// Objects merge key by key; any other override value (including arrays)
// replaces the environment's. An empty envConfig is treated as an empty object.
func Merge(envConfig, override string) (string, error) {
	base := map[string]any{}
	if strings.TrimSpace(envConfig) != "" {
		if err := json.Unmarshal([]byte(envConfig), &base); err != nil {
			return "", fmt.Errorf("invalid environment configuration: %w", err)
		}
	}
	over := map[string]any{}
	if err := json.Unmarshal([]byte(override), &over); err != nil {
		return "", fmt.Errorf("invalid override: %w", err)
	}
	out, err := json.MarshalIndent(mergeMaps(base, over), "", "  ")
	if err != nil {
		return "", fmt.Errorf("error serializing configuration: %w", err)
	}
	return string(out), nil
}

func mergeMaps(base, over map[string]any) map[string]any {
	if base == nil { // a literal JSON null environment config decodes to a nil map
		base = map[string]any{}
	}
	for k, ov := range over {
		om, oIsMap := ov.(map[string]any)
		bm, bIsMap := base[k].(map[string]any)
		if oIsMap && bIsMap {
			base[k] = mergeMaps(bm, om)
		} else {
			base[k] = ov
		}
	}
	return base
}
