package serviceconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/config"
)

// Field-level overrides. The bug (issue #1066) was that saving ONE field stored
// the whole section as source=db, so every other field in it — port, listener,
// host — stopped following flags and environment variables from then on.

func set(kv map[string]any) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(kv))
	for k, v := range kv {
		raw, err := json.Marshal(v)
		if err != nil {
			panic(err)
		}
		out[k] = raw
	}
	return out
}

func newAPIManager(t *testing.T) *ServiceConfigManager {
	t.Helper()
	m := NewServiceConfigManager(setupTestDB(t))
	require.NoError(t, m.Seed(config.ServiceAPI, apiServiceParams(9000), NoEnvironmentID))
	return m
}

// ── the reported bug ─────────────────────────────────────────────────────────

func TestPatchOneFieldDoesNotFreezeTheRest(t *testing.T) {
	m := newAPIManager(t)

	// The operator changes the log level and nothing else.
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"LogLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	// Next boot passes --port 9002.
	boot := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, boot, NoEnvironmentID))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot, NoEnvironmentID))

	assert.Equal(t, 9002, boot.Service.Port, "an untouched field must keep following its flag")
	assert.Equal(t, "debug", boot.Service.LogLevel, "the pinned field must keep the operator's value")
}

func TestPinnedFieldBeatsTheFlag(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"Port": 9100}), nil, NoEnvironmentID)
	require.NoError(t, err)

	boot := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, boot, NoEnvironmentID))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot, NoEnvironmentID))

	assert.Equal(t, 9100, boot.Service.Port, "the point of pinning a field is that it wins")
}

// The stored value is what the UI shows as the current setting, so a field that
// follows the process has to show what the process is actually running.
func TestSeedRefreshesUnpinnedFieldsInTheStoredValue(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"LogLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	require.NoError(t, m.Seed(config.ServiceAPI, apiServiceParams(9002), NoEnvironmentID))

	row, err := m.GetSection(config.ServiceAPI, "service", NoEnvironmentID)
	require.NoError(t, err)
	var stored config.YAMLConfigurationService
	require.NoError(t, json.Unmarshal([]byte(row.Value), &stored))
	assert.Equal(t, 9002, stored.Port, "an unpinned field must mirror the running process, not the first boot")
	assert.Equal(t, "debug", stored.LogLevel, "a pinned field must not be refreshed")
}

func TestSeedRefreshesRowsThatPinNothing(t *testing.T) {
	m := newAPIManager(t)
	require.NoError(t, m.Seed(config.ServiceAPI, apiServiceParams(9002), NoEnvironmentID))

	row, err := m.GetSection(config.ServiceAPI, "service", NoEnvironmentID)
	require.NoError(t, err)
	assert.Equal(t, SourceYAML, row.Source)
	var stored config.YAMLConfigurationService
	require.NoError(t, json.Unmarshal([]byte(row.Value), &stored))
	assert.Equal(t, 9002, stored.Port)
}

func TestSeedLeavesTheValueAloneWhenNothingChanged(t *testing.T) {
	m := newAPIManager(t)
	before, err := m.GetSection(config.ServiceAPI, "service", NoEnvironmentID)
	require.NoError(t, err)

	require.NoError(t, m.Seed(config.ServiceAPI, apiServiceParams(9000), NoEnvironmentID))

	after, err := m.GetSection(config.ServiceAPI, "service", NoEnvironmentID)
	require.NoError(t, err)
	// Byte-identical, not just equivalent: the refresh must not reformat or
	// reorder a value it has no reason to change. (UpdatedAt is deliberately
	// not asserted — Seed's pre-existing metadata sync touches every row on
	// every boot, with or without a refresh.)
	assert.Equal(t, before.Value, after.Value)
}

// ── rows from before pins existed ────────────────────────────────────────────

// A legacy source=db row has no pin list. Treating that as "pin nothing" would
// silently drop the operator's edits on upgrade, and the original YAML is gone,
// so the only safe reading is "pin everything" — exactly yesterday's behavior.
func TestLegacyRowKeepsPinningEverything(t *testing.T) {
	m := newAPIManager(t)
	require.NoError(t, m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceAPI, "service").
		Updates(map[string]any{
			"value":  `{"Listener":"127.0.0.1","Port":9000,"Host":"osctrl.net","LogLevel":"info"}`,
			"source": SourceDB, // no overrides column: a row written by an older release
		}).Error)

	boot := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, boot, NoEnvironmentID))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot, NoEnvironmentID))

	assert.Equal(t, 9000, boot.Service.Port, "upgrading must not change what an existing row does")
}

// The reporter's way out: release one field of a legacy row without losing the
// rest of the operator's edits.
func TestResetReleasesOneFieldOfALegacyRow(t *testing.T) {
	m := newAPIManager(t)
	require.NoError(t, m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceAPI, "service").
		Updates(map[string]any{
			"value":  `{"Listener":"127.0.0.1","Port":9000,"Host":"osctrl.net","LogLevel":"debug"}`,
			"source": SourceDB,
		}).Error)

	_, err := m.PatchSection(config.ServiceAPI, "service", nil, []string{"Port"}, NoEnvironmentID)
	require.NoError(t, err)

	boot := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, boot, NoEnvironmentID))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot, NoEnvironmentID))

	assert.Equal(t, 9002, boot.Service.Port, "the released field follows its flag again")
	assert.Equal(t, "debug", boot.Service.LogLevel, "fields that were not released stay pinned")
}

func TestReleasingTheLastPinReturnsTheRowToYAML(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"LogLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	row, err := m.PatchSection(config.ServiceAPI, "service", nil, []string{"LogLevel"}, NoEnvironmentID)
	require.NoError(t, err)

	assert.Equal(t, SourceYAML, row.Source, "no pins left means nothing differs from the file")
	assert.Empty(t, row.Overrides)
	pending, err := m.HasPendingChanges(config.ServiceAPI, NoEnvironmentID)
	require.NoError(t, err)
	assert.False(t, pending, "the UI must stop offering to write changes that no longer exist")
}

// Whole-section replacement cannot say what the caller meant to pin, so it
// still pins everything — and must clear any earlier narrower pin list.
func TestWholeReplacementPinsEverythingAgain(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"LogLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	row, err := m.UpdateSection(config.ServiceAPI, "service",
		`{"Listener":"127.0.0.1","Port":9000,"Host":"osctrl.net","LogLevel":"warn"}`, NoEnvironmentID)
	require.NoError(t, err)
	assert.Empty(t, row.Overrides)

	boot := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, boot, NoEnvironmentID))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot, NoEnvironmentID))
	assert.Equal(t, 9000, boot.Service.Port)
}

func TestUnreadablePinListPinsEverything(t *testing.T) {
	// Failing to "pin nothing" would drop the operator's edits on the next boot.
	sc := ServiceConfig{Source: SourceDB, Overrides: `{not json`}
	assert.True(t, sc.pinSet().all)
}

func TestYAMLSourceRowNeverPinsEvenWithAStaleColumn(t *testing.T) {
	sc := ServiceConfig{Source: SourceYAML, Overrides: `["Port"]`}
	assert.False(t, sc.pinSet().has("Port"))
}

// ── patch validation ─────────────────────────────────────────────────────────

func TestPatchRejectsAnUnknownField(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"Prot": 9100}), nil, NoEnvironmentID)
	assert.ErrorIs(t, err, ErrUnknownField, "pinning a field that does not exist would be a silent no-op")

	_, err = m.PatchSection(config.ServiceAPI, "service", nil, []string{"Prot"}, NoEnvironmentID)
	assert.ErrorIs(t, err, ErrUnknownField)
}

func TestPatchMatchesFieldNamesCaseInsensitively(t *testing.T) {
	m := newAPIManager(t)
	// encoding/json matches keys case-insensitively, so a YAML-style key must
	// land on the existing field instead of creating a second one.
	row, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"logLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	fields, err := orderedFields(row.Value)
	require.NoError(t, err)
	count := 0
	for _, f := range fields {
		if norm(f.Key) == "loglevel" {
			count++
			assert.Equal(t, "LogLevel", f.Key, "stored under the spelling the section already uses")
		}
	}
	assert.Equal(t, 1, count)
	assert.JSONEq(t, `["LogLevel"]`, row.Overrides)
}

func TestPatchRejectsSetAndResetOfTheSameField(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"Port": 9100}), []string{"port"}, NoEnvironmentID)
	assert.Error(t, err)
}

func TestPatchRejectsTheSameFieldTwice(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", map[string]json.RawMessage{
		"Port": json.RawMessage(`9100`), "port": json.RawMessage(`9200`),
	}, nil, NoEnvironmentID)
	assert.Error(t, err, "two spellings of one field is ambiguous, not a merge")
}

func TestPatchRejectsAnEmptyPatch(t *testing.T) {
	m := newAPIManager(t)
	_, err := m.PatchSection(config.ServiceAPI, "service", nil, nil, NoEnvironmentID)
	assert.ErrorIs(t, err, ErrEmptyPatch)
}

func TestPatchRefusesNonEditableSections(t *testing.T) {
	m := newAPIManager(t)
	require.False(t, m.IsEditable(config.ServiceAPI, "db"))
	_, err := m.PatchSection(config.ServiceAPI, "db", set(map[string]any{"Password": "x"}), nil, NoEnvironmentID)
	assert.ErrorIs(t, err, ErrSectionNotEditable)
}

func TestPatchRunsTheSameValidationAsWholeReplacement(t *testing.T) {
	m := NewServiceConfigManager(setupTestDB(t))
	require.NoError(t, m.Seed(config.ServiceTLS, testTLSParams(), NoEnvironmentID))
	// Logger is a bool in the osquery section; a string must be rejected here
	// exactly as UpdateSection rejects it, not stored and discovered at boot.
	_, err := m.PatchSection(config.ServiceTLS, "osquery", set(map[string]any{"Logger": "yes please"}), nil, NoEnvironmentID)
	assert.Error(t, err)

	row, getErr := m.GetSection(config.ServiceTLS, "osquery", NoEnvironmentID)
	require.NoError(t, getErr)
	assert.Equal(t, SourceYAML, row.Source, "a rejected patch must leave the row untouched")
}

func TestPatchOnANonObjectSectionIsRefused(t *testing.T) {
	m := newAPIManager(t)
	require.NoError(t, m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceAPI, "service").
		Update("value", `[1,2,3]`).Error)
	_, err := m.PatchSection(config.ServiceAPI, "service", set(map[string]any{"Port": 1}), nil, NoEnvironmentID)
	assert.ErrorIs(t, err, ErrSectionNotPatchable)
}

// ── persisting to the YAML file ──────────────────────────────────────────────

func TestPersistToFileClearsPins(t *testing.T) {
	m := setupFileTestDB(t)
	path := filepath.Join(t.TempDir(), "tls.yml")
	params := testTLSParams()
	require.NoError(t, m.Seed(config.ServiceTLS, params, NoEnvironmentID))
	require.NoError(t, config.GenerateTLSConfigFile(path, params, true))

	_, err := m.PatchSection(config.ServiceTLS, "debug", set(map[string]any{"EnableHTTP": true}), nil, NoEnvironmentID)
	require.NoError(t, err)
	require.NoError(t, m.PersistToFile(config.ServiceTLS, path, testTLSParams(), NoEnvironmentID))

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(written), "enableHttp: true", "the pinned field is what gets written")

	row, err := m.GetSection(config.ServiceTLS, "debug", NoEnvironmentID)
	require.NoError(t, err)
	assert.Equal(t, SourceYAML, row.Source)
	assert.Empty(t, row.Overrides, "a pin list must not outlive the edit it described")
}

// ── pin helpers ──────────────────────────────────────────────────────────────

func TestOrderedFieldsPreservesOrderAndRejectsNonObjects(t *testing.T) {
	fields, err := orderedFields(`{"b":1,"a":{"x":[1,2]},"c":"z"}`)
	require.NoError(t, err)
	var keys []string
	for _, f := range fields {
		keys = append(keys, f.Key)
	}
	assert.Equal(t, []string{"b", "a", "c"}, keys, "document order, not alphabetical")
	assert.JSONEq(t, `{"x":[1,2]}`, string(fields[1].Raw))

	_, err = orderedFields(`[1,2]`)
	assert.Error(t, err)
	_, err = orderedFields(`{"a":1} trailing`)
	assert.Error(t, err, "trailing garbage is reported, not ignored")
	_, err = orderedFields(``)
	assert.Error(t, err)
}

func TestFilterToPinsKeepsOnlyPinnedFields(t *testing.T) {
	pins := pinSet{keys: map[string]bool{"port": true}}
	assert.JSONEq(t, `{"Port":1}`, filterToPins(`{"Port":1,"Host":"h"}`, pins))
	assert.JSONEq(t, `{"Port":1,"Host":"h"}`, filterToPins(`{"Port":1,"Host":"h"}`, pinSet{all: true}))
	assert.Equal(t, `[1]`, filterToPins(`[1]`, pins), "an array cannot be filtered and is returned whole")
}

func TestMergeUnpinnedTakesFreshForUnpinnedAndStoredForPinned(t *testing.T) {
	pins := pinSet{keys: map[string]bool{"loglevel": true}}
	got, changed := mergeUnpinned(
		`{"Port":9000,"LogLevel":"debug","Gone":1}`,
		`{"Port":9002,"LogLevel":"info","New":true}`, pins)
	assert.True(t, changed)
	assert.JSONEq(t, `{"Port":9002,"LogLevel":"debug","New":true}`, got,
		"unpinned follows the process, pinned keeps the operator's value, removed fields drop, new ones appear")

	same, changed := mergeUnpinned(`{"Port":9002}`, `{"Port": 9002}`, pinSet{keys: map[string]bool{}})
	assert.False(t, changed, "whitespace must not count as a change")
	assert.Equal(t, `{"Port":9002}`, same)
}

// ── the filter in Resolve, independent of Seed ───────────────────────────────

// Seed refreshes unpinned fields before Resolve runs, which makes applying a
// whole row look harmless — so a test that goes through Seed cannot tell the
// filter from its absence. This one calls Resolve alone, with a stored value
// that disagrees with the live config on an UNPINNED field.
func TestResolveAppliesOnlyPinnedFields(t *testing.T) {
	m := newAPIManager(t)
	require.NoError(t, m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceAPI, "service").
		Updates(map[string]any{
			// Port differs from the live config but is NOT pinned.
			"value":     `{"Listener":"127.0.0.1","Port":9999,"Host":"osctrl.net","LogLevel":"debug"}`,
			"source":    SourceDB,
			"overrides": `["LogLevel"]`,
		}).Error)

	live := apiServiceParams(9002)
	require.NoError(t, m.Resolve(config.ServiceAPI, live, NoEnvironmentID))

	assert.Equal(t, 9002, live.Service.Port, "an unpinned field must not be taken from the row")
	assert.Equal(t, "debug", live.Service.LogLevel)
}

// "Write to disk" resolves against a FRESH load of the YAML file and never runs
// Seed. If Resolve applied the whole stored row there, the values the running
// process got from flags or environment variables would be written into the
// operator's YAML file. Only what the operator pinned may reach the file.
func TestPersistToFileDoesNotBakeFlagsIntoTheFile(t *testing.T) {
	m := setupFileTestDB(t)
	path := filepath.Join(t.TempDir(), "tls.yml")

	// The file on disk says port 9000.
	fileParams := testTLSParams()
	require.NoError(t, config.GenerateTLSConfigFile(path, fileParams, true))

	// The running process was started with --port 9002, so its row says 9002.
	running := testTLSParams()
	running.Service.Port = 9002
	require.NoError(t, m.Seed(config.ServiceTLS, running, NoEnvironmentID))

	// The operator changes one unrelated field.
	_, err := m.PatchSection(config.ServiceTLS, "service", set(map[string]any{"LogLevel": "debug"}), nil, NoEnvironmentID)
	require.NoError(t, err)

	require.NoError(t, m.PersistToFile(config.ServiceTLS, path, testTLSParams(), NoEnvironmentID))

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(written), "logLevel: debug", "the pinned field is written")
	assert.Contains(t, string(written), "port: 9000", "the file keeps its own port")
	assert.NotContains(t, string(written), "port: 9002", "a flag value must never be persisted into the YAML file")
}
