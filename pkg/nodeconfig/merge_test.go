package nodeconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mergeToMap(t *testing.T, env, override string) map[string]any {
	t.Helper()
	out, err := Merge(env, override)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &m))
	return m
}

func TestMergeOptionsKeyByKey(t *testing.T) {
	m := mergeToMap(t, `{"options":{"a":1,"b":2}}`, `{"options":{"b":3,"c":4}}`)
	assert.Equal(t, map[string]any{"a": 1.0, "b": 3.0, "c": 4.0}, m["options"])
}

func TestMergeScheduleByName(t *testing.T) {
	env := `{"schedule":{"q1":{"interval":60,"query":"select 1"}}}`
	override := `{"schedule":{"q1":{"interval":10},"q2":{"query":"select 2","interval":30}}}`
	sched := mergeToMap(t, env, override)["schedule"].(map[string]any)
	assert.Equal(t, map[string]any{"interval": 10.0, "query": "select 1"}, sched["q1"])
	assert.Equal(t, map[string]any{"interval": 30.0, "query": "select 2"}, sched["q2"])
}

func TestMergeArraysReplaced(t *testing.T) {
	m := mergeToMap(t, `{"decorators":{"load":["a","b"]}}`, `{"decorators":{"load":["c"]}}`)
	assert.Equal(t, map[string]any{"load": []any{"c"}}, m["decorators"])
}

func TestMergeAddsTopLevelKeys(t *testing.T) {
	m := mergeToMap(t, `{"options":{"a":1}}`, `{"file_paths":{"etc":["/etc/%%"]}}`)
	assert.Equal(t, map[string]any{"etc": []any{"/etc/%%"}}, m["file_paths"])
	assert.Contains(t, m, "options")
}

func TestMergeEmptyEnvironment(t *testing.T) {
	override := `{"options":{"verbose":true}}`
	m := mergeToMap(t, "", override)
	assert.Equal(t, map[string]any{"options": map[string]any{"verbose": true}}, m)
}

func TestMergeNullEnvironment(t *testing.T) {
	m := mergeToMap(t, `null`, `{"options":{"verbose":true}}`)
	assert.Equal(t, map[string]any{"options": map[string]any{"verbose": true}}, m)
}

func TestMergeInvalidEnvironment(t *testing.T) {
	_, err := Merge("{", `{}`)
	assert.Error(t, err)
}

func TestMergeInvalidOverride(t *testing.T) {
	_, err := Merge(`{}`, `{`)
	assert.Error(t, err)
}

func TestMergeEmptyOverride(t *testing.T) {
	env := `{"options":{"a":1},"schedule":{"q":{"interval":5}}}`
	assert.JSONEq(t, env, mustMerge(t, env, `{}`))
}

func TestMergeIndented(t *testing.T) {
	assert.Equal(t, "{\n  \"a\": 1\n}", mustMerge(t, `{}`, `{"a":1}`))
}

func mustMerge(t *testing.T, env, override string) string {
	t.Helper()
	out, err := Merge(env, override)
	require.NoError(t, err)
	return out
}
