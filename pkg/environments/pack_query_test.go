package environments

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func packsEnv(t *testing.T, packs string) (*EnvManager, string) {
	t.Helper()
	envs := CreateEnvironment(setupTestDB(t))
	env := envs.Empty("dev", "dev.example.com")
	require.NoError(t, envs.Create(&env))
	require.NoError(t, envs.UpdatePacks(env.Name, packs))
	return envs, env.Name
}

func TestAddQueryToPackConfSurvivesDecodedPacks(t *testing.T) {
	// Packs come back from the database as map[string]interface{}; a pack with
	// no queries has a nil Queries map.
	envs, name := packsEnv(t, `{"p1":{"platform":"linux","queries":{"a":{"query":"select 1","interval":60}}},"empty":{"platform":"darwin"}}`)
	require.NotPanics(t, func() {
		require.NoError(t, envs.AddQueryToPackConf(name, "p1", "b", ScheduleQuery{Query: "select 2", Interval: "30"}))
		require.NoError(t, envs.AddQueryToPackConf(name, "empty", "c", ScheduleQuery{Query: "select 3", Interval: "10"}))
	})
	env, err := envs.Get(name)
	require.NoError(t, err)
	packs, err := envs.GenPacksEntries([]byte(env.Packs))
	require.NoError(t, err)
	require.Len(t, packs["p1"].Queries, 2)
	require.Equal(t, "linux", packs["p1"].Platform, "other pack fields are kept")
	require.Equal(t, "select 3", packs["empty"].Queries["c"].Query)
}

func TestRemoveQueryFromPackConf(t *testing.T) {
	envs, name := packsEnv(t, `{"p1":{"queries":{"a":{"query":"select 1"},"b":{"query":"select 2"}}},"empty":{}}`)
	require.NotPanics(t, func() {
		require.NoError(t, envs.RemoveQueryFromPackConf(name, "p1", "a"))
		require.NoError(t, envs.RemoveQueryFromPackConf(name, "empty", "zzz"))
	})
	env, err := envs.Get(name)
	require.NoError(t, err)
	packs, err := envs.GenPacksEntries([]byte(env.Packs))
	require.NoError(t, err)
	require.Len(t, packs["p1"].Queries, 1)
	require.Contains(t, packs["p1"].Queries, "b")
}

func TestPackQueryConfRejectsMissingAndLocalPacks(t *testing.T) {
	envs, name := packsEnv(t, `{"local":"/etc/osquery/pack.conf"}`)
	for _, pack := range []string{"nope", "local"} {
		require.NotPanics(t, func() {
			require.ErrorContains(t, envs.AddQueryToPackConf(name, pack, "q", ScheduleQuery{Query: "select 1"}), pack)
			require.ErrorContains(t, envs.RemoveQueryFromPackConf(name, pack, "q"), pack)
		})
	}
	require.ErrorContains(t, envs.AddQueryToPackConf(name, "local", "q", ScheduleQuery{}), "local pack")
	env, err := envs.Get(name)
	require.NoError(t, err)
	require.JSONEq(t, `{"local":"/etc/osquery/pack.conf"}`, env.Packs, "failed calls must not change the packs")
}

func TestPackQueryEditsAreLossless(t *testing.T) {
	const stored = `{"p1":{"platform":"linux","version":"5.0.0","shard":50,"discovery":["select 1"],"description":"d","queries":{"a":{"query":"select 1","interval":60,"description":"qa","value":"v","denylist":false,"extra":{"x":[1,2]}},"b":{"query":"select 2","interval":10,"platform":"darwin","shard":5}}},"p2":{"custom":true,"queries":{"z":{"query":"select 9","interval":1,"snapshot":true,"note":"n"}}}}`
	envs, name := packsEnv(t, stored)
	packsOf := func() map[string]interface{} {
		env, err := envs.Get(name)
		require.NoError(t, err)
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(env.Packs), &m))
		return m
	}
	want := func() map[string]interface{} {
		var m map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(stored), &m))
		return m
	}()

	require.NoError(t, envs.AddQueryToPackConf(name, "p1", "c", ScheduleQuery{Query: "select 3", Interval: "30"}))
	got := packsOf()
	require.Equal(t, want["p2"], got["p2"], "other packs untouched")
	p1 := got["p1"].(map[string]interface{})
	qs := p1["queries"].(map[string]interface{})
	require.Equal(t, map[string]interface{}{"query": "select 3", "interval": float64(30)}, qs["c"])
	delete(qs, "c")
	require.Equal(t, want["p1"], got["p1"], "unmodelled pack and query keys survive an add")

	require.NoError(t, envs.RemoveQueryFromPackConf(name, "p1", "b"))
	got = packsOf()
	delete(want["p1"].(map[string]interface{})["queries"].(map[string]interface{}), "b")
	require.Equal(t, want["p2"], got["p2"])
	// c was added above and is still there; everything else matches
	delete(got["p1"].(map[string]interface{})["queries"].(map[string]interface{}), "c")
	require.Equal(t, want["p1"], got["p1"], "unmodelled keys survive a remove")
}

// An edit is saved even when another stored section is malformed; the error
// says so instead of reading like the edit failed.
func TestEditSectionSavedButRefreshFails(t *testing.T) {
	envs, name := packsEnv(t, `{}`)
	require.NoError(t, envs.UpdateSchedule(name, `{}`))
	require.NoError(t, envs.UpdateOptions(name, `{}`))
	require.NoError(t, envs.UpdateATC(name, `{}`))
	require.NoError(t, envs.UpdateDecorators(name, `[]`))
	err := envs.AddScheduleConfQuery(name, "q", ScheduleQuery{Query: "select 1", Interval: "60"})
	require.ErrorContains(t, err, "schedule saved, but refreshing the assembled configuration failed")
	require.ErrorContains(t, err, "error structuring decorators")
	env, err := envs.Get(name)
	require.NoError(t, err)
	require.Contains(t, env.Schedule, "select 1")
}

func TestAddQueryToPackConfReplacesModelledFields(t *testing.T) {
	envs, name := packsEnv(t, `{"p1":{"queries":{"a":{"query":"select 1","interval":60,"snapshot":true,"removed":true,"denylist":true,"platform":"linux","version":"5.0","shard":5,"custom":"keep"}}}}`)
	require.NoError(t, envs.AddQueryToPackConf(name, "p1", "a", ScheduleQuery{Query: "select 2", Interval: "30"}))
	env, err := envs.Get(name)
	require.NoError(t, err)
	var packs map[string]map[string]map[string]map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(env.Packs), &packs))
	q := packs["p1"]["queries"]["a"]
	require.Equal(t, "select 2", q["query"])
	for _, k := range []string{"snapshot", "removed", "denylist", "platform", "version", "shard"} {
		require.NotContains(t, q, k, "re-add clears %s", k)
	}
	require.Equal(t, "keep", q["custom"], "keys outside ScheduleQuery survive")
}
