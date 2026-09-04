package config

import "fmt"

// ConfigVersion is the version of the YAML configuration schema this
// binary understands. Bump it whenever a field is added, renamed, or
// removed from any YAMLConfiguration* struct so services can warn
// operators whose files predate the change. The sample files in
// deploy/config and the files written by the config-generate
// subcommands carry the same number in their top-level "version" field.
const ConfigVersion = 3

// ConfigVersionWarning returns a warning when the "version" field of a
// YAML configuration file does not match ConfigVersion, or an empty
// string when it does. A file without the field reads as 0 and counts
// as predating versioned configuration. Version skew is never an error:
// it is operator-visible information, not a reason to refuse starting.
func ConfigVersionWarning(fileVersion int) string {
	switch {
	case fileVersion == ConfigVersion:
		return ""
	case fileVersion == 0:
		return fmt.Sprintf("configuration file has no version field — fields added since the file was written may be missing; compare with config-generate output and add 'version: %d'", ConfigVersion)
	case fileVersion < ConfigVersion:
		return fmt.Sprintf("configuration file version %d is older than supported version %d — fields added since version %d may be missing; compare with config-generate output", fileVersion, ConfigVersion, fileVersion)
	default:
		return fmt.Sprintf("configuration file version %d is newer than supported version %d — fields this binary does not know are ignored; upgrade osctrl", fileVersion, ConfigVersion)
	}
}
