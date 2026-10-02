package serviceconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jmpsec/osctrl/pkg/config"
)

// A database row beating --port with no word about it is what issue #1066
// reported. These tests pin that the override is explained, not that it is
// removed: the precedence itself is what makes "Apply & Restart" work.

func TestDiffSections(t *testing.T) {
	tests := []struct {
		name      string
		before    string
		after     string
		wantKeys  []string
		wantWhole bool
	}{
		{"identical sections report nothing", `{"port":9000}`, `{"port":9000}`, nil, false},
		{"one field differs", `{"port":9002,"logLevel":"info"}`, `{"port":9000,"logLevel":"info"}`, []string{"port"}, false},
		{"several fields differ, sorted by key", `{"port":9002,"host":"a","logLevel":"info"}`, `{"port":9000,"host":"b","logLevel":"info"}`, []string{"host", "port"}, false},
		{"a field only the row sets", `{"port":9000}`, `{"port":9000,"logFormat":"json"}`, []string{"logFormat"}, false},
		{"arrays cannot be compared field by field", `[{"a":1}]`, `[{"a":2}]`, nil, true},
		{"unparseable input degrades to whole-section", `not json`, `{"port":1}`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes, whole := diffSections(tt.before, tt.after)
			assert.Equal(t, tt.wantWhole, whole)
			var keys []string
			for _, c := range changes {
				keys = append(keys, c.Key)
			}
			assert.Equal(t, tt.wantKeys, keys)
		})
	}
}

func TestDescribeChangesShowsOldAndNewValues(t *testing.T) {
	changes, _ := diffSections(`{"port":9002}`, `{"port":9000}`)
	assert.Equal(t, "port (9002 -> 9000)", describeChanges(changes, true))
}

func TestDescribeChangesHidesValuesWhenAsked(t *testing.T) {
	changes, _ := diffSections(`{"password":"old-secret"}`, `{"password":"new-secret"}`)
	got := describeChanges(changes, false)
	assert.Equal(t, "password", got)
	assert.NotContains(t, got, "secret")
}

func TestDescribeChangesTruncatesLongValues(t *testing.T) {
	long := `"` + strings.Repeat("x", 500) + `"`
	changes, _ := diffSections(`{"k":"short"}`, `{"k":`+long+`}`)
	got := describeChanges(changes, true)
	assert.Less(t, len(got), 200, "a log line must not carry a whole config blob")
	assert.Contains(t, got, "...")
}

// captureLog routes the global zerolog logger into a buffer for one test and
// restores both the logger and the global level afterwards.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevLogger, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(&buf)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})
	return &buf
}

func apiServiceParams(port int) *config.ServiceParameters {
	return &config.ServiceParameters{Service: &config.YAMLConfigurationService{
		Listener: "127.0.0.1", Port: port, Host: "osctrl.net", LogLevel: "info",
	}}
}

// TestResolveLogsTheOverrideThatHidesAFlag is the issue #1066 scenario end to
// end: an operator saved the service section once, later passes --port 9002,
// and the service binds the saved port. The behavior is unchanged; the log now
// says why.
func TestResolveLogsTheOverrideThatHidesAFlag(t *testing.T) {
	m := NewServiceConfigManager(setupTestDB(t))

	boot1 := apiServiceParams(9000)
	require.NoError(t, m.Seed(config.ServiceAPI, boot1, 0))
	// The Service Config page submits the whole section, not just the field
	// that was changed.
	saved, err := json.Marshal(boot1.Service)
	require.NoError(t, err)
	_, err = m.UpdateSection(config.ServiceAPI, "service", string(saved), 0)
	require.NoError(t, err)

	buf := captureLog(t)
	boot2 := apiServiceParams(9002) // --port 9002
	require.NoError(t, m.Seed(config.ServiceAPI, boot2, 0))
	require.NoError(t, m.Resolve(config.ServiceAPI, boot2, 0))

	assert.Equal(t, 9000, boot2.Service.Port, "the stored row still wins; this change explains it, it does not alter it")
	out := buf.String()
	assert.Contains(t, out, `"section":"service"`)
	// Keys are the stored JSON keys, which for these structs are the Go field
	// names — the same spelling the Service Config page shows the operator.
	assert.Contains(t, out, "Port (9002 -> 9000)", "the log must name the field and both values")
	assert.Contains(t, out, "overrides flags, environment and YAML")
	// This row was replaced as a whole (UpdateSection), so it is a legacy-style
	// pin-everything row, and the log must say so rather than let the operator
	// wonder why a field they never touched moved.
	assert.Contains(t, out, "pins EVERY field", "the log should explain why untouched fields moved too")
}

func TestResolveStaysQuietWhenNothingIsOverridden(t *testing.T) {
	m := NewServiceConfigManager(setupTestDB(t))

	// No edited row at all.
	buf := captureLog(t)
	clean := apiServiceParams(9002)
	require.NoError(t, m.Seed(config.ServiceAPI, clean, 0))
	require.NoError(t, m.Resolve(config.ServiceAPI, clean, 0))
	assert.Empty(t, buf.String(), "no database row, so nothing to explain")
	assert.Equal(t, 9002, clean.Service.Port)
}

func TestResolveStaysQuietWhenTheRowMatchesWhatTheProcessHad(t *testing.T) {
	m := NewServiceConfigManager(setupTestDB(t))

	boot1 := apiServiceParams(9000)
	require.NoError(t, m.Seed(config.ServiceAPI, boot1, 0))
	saved, err := json.Marshal(boot1.Service)
	require.NoError(t, err)
	_, err = m.UpdateSection(config.ServiceAPI, "service", string(saved), 0)
	require.NoError(t, err)

	// Same values on the next boot: the row is applied but changes nothing, so
	// a log line would be noise.
	buf := captureLog(t)
	boot2 := apiServiceParams(9000)
	require.NoError(t, m.Resolve(config.ServiceAPI, boot2, 0))
	assert.Empty(t, buf.String())
}

// TestResolveNeverLogsValuesFromNonEditableSections guards the other half of
// the feature: a hand-written row in a credential section may still be applied,
// and its field names help explain a surprise, but its values must not reach a
// log.
func TestResolveNeverLogsValuesFromNonEditableSections(t *testing.T) {
	m := NewServiceConfigManager(setupTestDB(t))

	boot1 := &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{Port: 9000},
		DB:      &config.YAMLConfigurationDB{Type: config.DBTypeSQLite, Name: "osctrl", Password: "from-yaml"},
	}
	require.NoError(t, m.Seed(config.ServiceAPI, boot1, 0))
	require.False(t, m.IsEditable(config.ServiceAPI, "db"), "this test needs a section the API refuses to edit")

	// The API would reject this write; a direct database edit would not.
	require.NoError(t, m.DB.Model(&ServiceConfig{}).
		Where("service = ? AND name = ?", config.ServiceAPI, "db").
		Updates(map[string]any{
			"value":  `{"type":"sqlite","name":"osctrl","password":"hunter2-from-the-db-row"}`,
			"source": SourceDB,
		}).Error)

	buf := captureLog(t)
	boot2 := &config.ServiceParameters{
		Service: &config.YAMLConfigurationService{Port: 9000},
		DB:      &config.YAMLConfigurationDB{Type: config.DBTypeSQLite, Name: "osctrl", Password: "from-yaml"},
	}
	require.NoError(t, m.Resolve(config.ServiceAPI, boot2, 0))

	out := buf.String()
	assert.Contains(t, out, `"section":"db"`)
	assert.Contains(t, out, "Password", "the field name is what explains the surprise")
	assert.NotContains(t, out, "hunter2-from-the-db-row", "the new value must never be logged")
	assert.NotContains(t, out, "from-yaml", "neither may the value it replaced")
}
