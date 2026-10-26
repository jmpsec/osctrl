package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/types"
)

// envCacheNote warns that direct-database edits cannot invalidate the shared
// Redis environment cache (see pkg/environments/env-cache.go).
const envCacheNote = "With --db the edit cannot invalidate the shared Redis environment cache, so osctrl-api and " +
	"osctrl-tls may keep serving the old environment for up to 5 minutes (60 while the database is degraded); " +
	"API mode invalidates immediately."

// envConfigEditNote is the help Description of every command that edits an
// environment configuration section.
const envConfigEditNote = "In API mode the edit is read-modify-write: the CLI reads the whole section, " +
	"changes it and writes the whole section back. It is not atomic: a change saved by someone else " +
	"in between (for example in the UI) is overwritten. " + envCacheNote

// envConfigSections maps a section to its field in the API config response.
var envConfigSections = map[string]func(types.EnvConfigResponse) string{
	environments.SectionOptions:    func(c types.EnvConfigResponse) string { return c.Options },
	environments.SectionSchedule:   func(c types.EnvConfigResponse) string { return c.Schedule },
	environments.SectionPacks:      func(c types.EnvConfigResponse) string { return c.Packs },
	environments.SectionDecorators: func(c types.EnvConfigResponse) string { return c.Decorators },
	environments.SectionATC:        func(c types.EnvConfigResponse) string { return c.ATC },
}

// editEnvConfigSection applies edit to one JSON configuration section of
// environment env and stores the result, in either mode. The result must be
// valid JSON. In API mode this is a GET then a whole-section PATCH: not atomic.
func editEnvConfigSection(env, section string, edit func(current string) (string, error)) error {
	get, ok := envConfigSections[section]
	if !ok {
		return fmt.Errorf("unknown configuration section %q", section)
	}
	checked := func(current string) (string, error) {
		updated, err := edit(current)
		if err == nil && !json.Valid([]byte(updated)) {
			err = fmt.Errorf("edited %s is not valid JSON", section)
		}
		return updated, err
	}
	if dbFlag {
		// Resolved before the edit, so a saved edit is never reported as failed.
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		if err := envs.EditSection(e.UUID, section, checked); err != nil {
			return err
		}
		// Same audit line the API handler writes for a config PATCH.
		auditlogsmgr.ConfAction(getShellUsername(), "config patch on env "+e.Name, "CLI", e.ID)
		return nil
	} else if apiFlag {
		cnf, err := osctrlAPI.GetEnvConfig(env)
		if err != nil {
			return err
		}
		updated, err := checked(get(cnf))
		if err != nil {
			return err
		}
		return osctrlAPI.PatchEnvConfig(env, section, updated)
	}
	return nil
}
