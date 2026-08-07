package logging

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestS3QueryKeyLayout(t *testing.T) {
	ts := time.UnixMilli(1700000000000)
	key := s3QueryKey("env-uuid", "q-123", "NODE-UUID", ts)
	require.Equal(t, "env-uuid/query/q-123/NODE-UUID:1700000000000.json", key)
}

func TestSplitQueryKey(t *testing.T) {
	env, uuid, name, ok := splitQueryKey("env-uuid/query/q-123/NODE-UUID:1700000000000.json")
	require.True(t, ok)
	require.Equal(t, "env-uuid", env)
	require.Equal(t, "q-123", name)
	require.Equal(t, "NODE-UUID", uuid)
}

func TestSplitQueryKeyRejectsBadKey(t *testing.T) {
	_, _, _, ok := splitQueryKey("env-uuid/query/q-123")
	require.False(t, ok)
}

func TestTsFromKey(t *testing.T) {
	ts, ok := tsFromKey("env-uuid/query/q-123/NODE-UUID:1700000000000.json")
	require.True(t, ok)
	require.Equal(t, time.UnixMilli(1700000000000), ts)
}

func TestDecodeNodeLogKeyStatusMatch(t *testing.T) {
	key := "env-uuid/status/NODE-UUID:1700000000000.json"
	entry, ok := decodeNodeLogKey(key, "NODE-UUID")
	require.True(t, ok)
	require.Equal(t, "NODE-UUID", entry.UUID)
	require.Equal(t, time.UnixMilli(1700000000000), entry.CreatedAt)
}

func TestDecodeNodeLogKeyStatusRejectsOtherUUID(t *testing.T) {
	key := "env-uuid/status/OTHER-UUID:1700000000000.json"
	_, ok := decodeNodeLogKey(key, "NODE-UUID")
	require.False(t, ok)
}

func TestDecodeNodeLogBodyStatus(t *testing.T) {
	logs := []types.LogStatusData{{HostIdentifier: "node-uuid", Line: 1, Message: "ok", Version: "5.13.1", Filename: "init.cpp", Severity: 0}}
	body, err := json.Marshal(logs)
	require.NoError(t, err)
	created := time.UnixMilli(1700000000000)
	row, err := decodeNodeLogBody(body, types.StatusLog, "env-uuid", "NODE-UUID", created)
	require.NoError(t, err)
	require.Equal(t, "NODE-UUID", row["uuid"])
	require.Equal(t, "env-uuid", row["environment"])
	require.Equal(t, created, row["created_at"])
	require.Equal(t, "1", row["line"])
	require.Equal(t, "ok", row["message"])
	require.Equal(t, "5.13.1", row["version"])
}

func TestDecodeNodeLogBodyResult(t *testing.T) {
	logs := []types.LogResultData{{HostIdentifier: "node-uuid", Name: "time", Action: "added", Columns: json.RawMessage(`{"foo":"bar"}`), Epoch: 0, Counter: 0}}
	body, err := json.Marshal(logs)
	require.NoError(t, err)
	row, err := decodeNodeLogBody(body, types.ResultLog, "env-uuid", "NODE-UUID", time.UnixMilli(1700000000000))
	require.NoError(t, err)
	require.Equal(t, "time", row["name"])
	require.Equal(t, "added", row["action"])
	require.Contains(t, row["columns"].(string), "foo")
}

func TestDecodeQueryLogRow(t *testing.T) {
	data := types.QueryWriteData{Name: "q-123", Result: json.RawMessage(`[{"version":"5.13.1"}]`), Status: 0}
	body, err := json.Marshal(data)
	require.NoError(t, err)
	row, err := decodeQueryLogRow(body, "env-uuid/query/q-123/NODE-UUID:1700000000000.json")
	require.NoError(t, err)
	require.Equal(t, "NODE-UUID", row.UUID)
	require.Equal(t, "env-uuid", row.Environment)
	require.Equal(t, "q-123", row.Name)
	require.Equal(t, 0, row.Status)
	require.Contains(t, row.Data, "5.13.1")
}

func TestDecodeQueryLogBodyMap(t *testing.T) {
	data := types.QueryWriteData{Name: "q-123", Result: json.RawMessage(`[{"version":"5.13.1"}]`), Status: 0}
	body, err := json.Marshal(data)
	require.NoError(t, err)
	item, err := decodeQueryLogBody(body, "env-uuid/query/q-123/NODE-UUID:1700000000000.json")
	require.NoError(t, err)
	require.Equal(t, "NODE-UUID", item["uuid"])
	require.Equal(t, "q-123", item["name"])
}

func TestNodeLogMatchesSearch(t *testing.T) {
	row := map[string]any{"message": "osquery started", "line": "1"}
	require.True(t, nodeLogMatchesSearch(row, types.StatusLog, "started"))
	require.False(t, nodeLogMatchesSearch(row, types.StatusLog, "nonexistent"))
}

func TestSortKeysDesc(t *testing.T) {
	keys := []string{
		"env/query/q/1:1000.json",
		"env/query/q/1:3000.json",
		"env/query/q/1:2000.json",
	}
	sortKeysDesc(keys)
	require.Equal(t, "env/query/q/1:3000.json", keys[0])
	require.Equal(t, "env/query/q/1:2000.json", keys[1])
	require.Equal(t, "env/query/q/1:1000.json", keys[2])
}

func TestDBLogReaderNodeLogsFallsBackToDB(t *testing.T) {
	// NewDBLogReader with a nil DB should not panic on construction; the
	// call itself would error, which is the existing behavior of
	// GetNodeLogs with a nil gorm.DB. We only assert the reader is the
	// concrete dbLogReader type.
	r := NewDBLogReader(nil)
	_, ok := r.(*dbLogReader)
	require.True(t, ok)
}

func TestS3QueryKeyLexicalOrder(t *testing.T) {
	// Verify that lexical ordering of keys within a prefix matches
	// chronological ordering — this is the invariant the reader relies
	// on for free pre-sorting.
	base := "env/query/q/uuid:"
	keys := []string{
		base + strconv.FormatInt(1700000000000, 10) + ".json",
		base + strconv.FormatInt(1700000000001, 10) + ".json",
		base + strconv.FormatInt(1699999999999, 10) + ".json",
	}
	require.True(t, strings.Compare(keys[0], keys[1]) < 0, "ts 0 < ts 1 should sort first")
	require.True(t, strings.Compare(keys[2], keys[0]) < 0, "ts -1 < ts 0 should sort first")
}
