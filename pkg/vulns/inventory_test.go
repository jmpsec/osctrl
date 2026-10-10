package vulns

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestInventory(t *testing.T) (*Inventory, *fixedClock) {
	t.Helper()
	clock := newClock()
	return &Inventory{DB: newTestDB(t), now: clock.now}, clock
}

func snapshot(name string, rows any) types.LogResultData {
	raw, _ := json.Marshal(rows)
	return types.LogResultData{Name: QueryPrefix + name, Action: "snapshot", Columns: raw}
}

func softwareOf(t *testing.T, inv *Inventory, node string) []NodeSoftware {
	t.Helper()
	var out []NodeSoftware
	require.NoError(t, inv.DB.Where("node_uuid = ?", node).Order("name").Find(&out).Error)
	return out
}

func TestIngestDebStoresSourcePackage(t *testing.T) {
	inv, _ := newTestInventory(t)
	inv.Ingest("NODE-1", 7, []types.LogResultData{snapshot(CategoryDeb, []map[string]string{
		{"name": "libssl3", "version": "3.0.11-1~deb12u1", "source": "openssl", "arch": "amd64"},
		{"name": "bash", "version": "5.2.15-2+b2", "source": "", "arch": "amd64"},
		{"name": "libfoo1", "version": "1.0-1", "source": "foo (1.0-0.1)", "arch": "amd64"},
	})})

	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 3)
	assert.Equal(t, "bash", sw[0].Name)
	assert.Equal(t, "", sw[0].SourceName)
	assert.Equal(t, "foo", sw[1].SourceName, "dpkg appends the source version in parentheses")
	assert.Equal(t, "openssl", sw[2].SourceName)
	assert.Equal(t, uint(7), sw[2].EnvironmentID)
	assert.Equal(t, CategoryDeb, sw[2].Category)

	var state NodeState
	require.NoError(t, inv.DB.First(&state, "node_uuid = ?", "NODE-1").Error)
	assert.False(t, state.InventoryAt.IsZero(), "a stored inventory marks the node for matching")
}

func TestIngestRPMBuildsEpochVersionRelease(t *testing.T) {
	inv, _ := newTestInventory(t)
	inv.Ingest("NODE-1", 1, []types.LogResultData{snapshot(CategoryRPM, []map[string]string{
		{"name": "openssl-libs", "version": "3.0.7", "release": "27.el9", "epoch": "1", "source": "openssl-3.0.7-27.el9.src.rpm", "arch": "x86_64", "vendor": "Red Hat, Inc."},
		{"name": "bash", "version": "5.1.8", "release": "9.el9", "epoch": "", "source": "bash-5.1.8-9.el9.src.rpm"},
	})})

	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 2)
	assert.Equal(t, "5.1.8-9.el9", sw[0].Version)
	assert.Equal(t, "bash", sw[0].SourceName)
	assert.Equal(t, "1:3.0.7-27.el9", sw[1].Version)
	assert.Equal(t, "openssl", sw[1].SourceName)
	assert.Equal(t, "Red Hat, Inc.", sw[1].Vendor)
}

func TestIngestReplacesTheCategorySnapshot(t *testing.T) {
	inv, _ := newTestInventory(t)
	inv.Ingest("NODE-1", 1, []types.LogResultData{
		snapshot(CategoryDeb, []map[string]string{{"name": "a", "version": "1"}, {"name": "b", "version": "1"}}),
		snapshot(CategoryPython, []map[string]string{{"name": "requests", "version": "2.31.0"}}),
	})
	inv.Ingest("NODE-1", 1, []types.LogResultData{snapshot(CategoryDeb, []map[string]string{{"name": "a", "version": "2"}})})

	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 2, "deb was replaced, python untouched")
	assert.Equal(t, "a", sw[0].Name)
	assert.Equal(t, "2", sw[0].Version)
	assert.Equal(t, "requests", sw[1].Name)
}

func TestIngestIgnoresDifferentialAndForeignResults(t *testing.T) {
	inv, _ := newTestInventory(t)
	added := snapshot(CategoryDeb, []map[string]string{{"name": "a", "version": "1"}})
	added.Action = "added"
	foreign := snapshot(CategoryDeb, []map[string]string{{"name": "a", "version": "1"}})
	foreign.Name = "osctrl:posture:packages"
	inv.Ingest("NODE-1", 1, []types.LogResultData{added, foreign})
	assert.Empty(t, softwareOf(t, inv, "NODE-1"))
}

// Truncating would make a host look patched. Over the limit, the previous
// inventory stays as it was.
func TestIngestRejectsOversizedSnapshotWithoutTouchingThePrevious(t *testing.T) {
	inv, _ := newTestInventory(t)
	inv.Ingest("NODE-1", 1, []types.LogResultData{snapshot(CategoryDeb, []map[string]string{{"name": "kept", "version": "1"}})})

	big := make([]map[string]string, MaxRowsPerCategory+1)
	for i := range big {
		big[i] = map[string]string{"name": fmt.Sprintf("p%d", i), "version": "1"}
	}
	inv.Ingest("NODE-1", 1, []types.LogResultData{snapshot(CategoryDeb, big)})

	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 1)
	assert.Equal(t, "kept", sw[0].Name)
}

func TestIngestOSRecordsThePlatform(t *testing.T) {
	inv, clock := newTestInventory(t)
	inv.Ingest("NODE-1", 3, []types.LogResultData{snapshot(CategoryOS, []map[string]string{
		{"name": "Ubuntu", "version": "22.04.4 LTS (Jammy Jellyfish)", "major": "22", "platform": "ubuntu"},
	})})
	var state NodeState
	require.NoError(t, inv.DB.First(&state, "node_uuid = ?", "NODE-1").Error)
	assert.Equal(t, "ubuntu", state.OSPlatform)
	assert.Equal(t, "22.04.4 LTS (Jammy Jellyfish)", state.OSVersion)
	assert.Equal(t, uint(3), state.EnvironmentID)
	assert.Equal(t, clock.t, state.InventoryAt.UTC(), "an OS change re-matches the node")
}

// osquery can log numbers as JSON numbers (--log_numerics_as_numbers).
func TestIngestAcceptsNumericColumns(t *testing.T) {
	inv, _ := newTestInventory(t)
	inv.Ingest("NODE-1", 1, []types.LogResultData{{Name: QueryPrefix + CategoryRPM, Action: "snapshot",
		Columns: json.RawMessage(`[{"name":"bash","version":"5.1.8","release":"9.el9","epoch":1}]`)}})
	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 1)
	assert.Equal(t, "1:5.1.8-9.el9", sw[0].Version)
}

func TestIngestClipsOverlongFields(t *testing.T) {
	inv, _ := newTestInventory(t)
	long := strings.Repeat("x", 400)
	inv.Ingest("NODE-1", 1, []types.LogResultData{snapshot(CategoryNPM, []map[string]string{{"name": long, "version": "1.0.0"}})})
	sw := softwareOf(t, inv, "NODE-1")
	require.Len(t, sw, 1)
	assert.Len(t, sw[0].Name, 255)
}

// Postgres rejects invalid UTF-8, so a cut in the middle of a multi-byte
// character would fail the whole snapshot.
func TestClipKeepsValidUTF8(t *testing.T) {
	s := strings.Repeat("a", 254) + "é" // 'é' is 2 bytes, straddling 255
	got := clip(s)
	assert.True(t, utf8.ValidString(got))
	assert.Equal(t, strings.Repeat("a", 254), got)
}
