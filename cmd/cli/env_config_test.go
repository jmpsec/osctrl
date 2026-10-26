package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

// storedConf is every configuration column of environment name.
func storedConf(t *testing.T, rig *parityRig, name string) map[string]string {
	t.Helper()
	env, err := rig.Envs.Get(name)
	require.NoError(t, err)
	return map[string]string{
		"options": env.Options, "schedule": env.Schedule, "packs": env.Packs,
		"decorators": env.Decorators, "atc": env.ATC, "configuration": env.Configuration,
	}
}

// envAuditRows returns, and deletes, the audit rows of environment name.
func envAuditRows(t *testing.T, rig *parityRig, name string) []auditlog.AuditLog {
	t.Helper()
	env, err := rig.Envs.Get(name)
	require.NoError(t, err)
	var rows []auditlog.AuditLog
	require.NoError(t, rig.DB.Where("environment_id = ?", env.ID).Find(&rows).Error)
	require.NoError(t, rig.DB.Unscoped().Where("environment_id = ?", env.ID).Delete(&auditlog.AuditLog{}).Error)
	return rows
}

// TestEnvConfigCommandsParity runs each configuration command in DB mode on
// environment pdb and in API mode on papi (same starting configuration) and
// requires the stored sections and the assembled configuration to be
// byte-identical after every step, with the same output or error, and exactly
// one configuration audit row per successful edit in each mode.
func TestEnvConfigCommandsParity(t *testing.T) {
	rig := newParityRig(t)
	for _, name := range []string{"pdb", "papi"} {
		rig.SeedEnv(name)
		require.NoError(t, rig.Envs.UpdateOptions(name, `{"keep_opt":"v"}`))
		require.NoError(t, rig.Envs.UpdateSchedule(name, `{"keep":{"query":"select 0","interval":10}}`))
		require.NoError(t, rig.Envs.UpdatePacks(name, `{"kept":{"platform":"darwin","custom":1,"queries":{"k":{"query":"select 9","interval":5,"custom":true}}}}`))
		require.NoError(t, rig.Envs.RefreshConfiguration(name))
	}
	require.Equal(t, storedConf(t, rig, "pdb"), storedConf(t, rig, "papi"))
	for _, step := range []struct {
		args    []string
		wantErr string
	}{
		{args: []string{"add-scheduled-query", "-Q", "q1", "-q", "select 1", "-i", "60", "-p", "linux", "-v", "5.0.0"}},
		{args: []string{"add-scheduled-query", "-Q", "keep", "-q", "select 00", "-i", "20"}},
		{args: []string{"add-posture-queries", "-p", "linux-server", "-i", "300"}},
		{args: []string{"add-posture-queries", "-p", "nope"}, wantErr: "unknown posture profile"},
		{args: []string{"remove-scheduled-query", "-q", "q1"}},
		{args: []string{"remove-scheduled-query", "-q", "missing"}},
		{args: []string{"add-scheduled-query", "-Q", "q2", "-q", "select 1"}, wantErr: "interval is required"},
		{args: []string{"add-osquery-option", "-o", "o_int", "-t", "int", "-i", "5"}},
		{args: []string{"add-osquery-option", "-o", "o_str", "-t", "string", "-s", "x"}},
		{args: []string{"add-osquery-option", "-o", "o_bool", "-t", "bool", "-b"}},
		{args: []string{"add-osquery-option", "-o", "o_f", "-t", "float"}, wantErr: "invalid type"},
		{args: []string{"remove-osquery-option", "-o", "o_str"}},
		{args: []string{"remove-osquery-option", "-o", "missing"}},
		{args: []string{"add-new-pack", "-p", "pk", "-P", "linux", "-v", "1.0", "-s", "10"}},
		{args: []string{"add-local-pack", "-p", "lp", "-P", "/etc/osquery/x.conf"}},
		{args: []string{"add-query-to-pack", "-p", "pk", "-Q", "pq", "-q", "select 2", "-i", "30"}},
		{args: []string{"add-query-to-pack", "-p", "kept", "-Q", "k", "-q", "select 99", "-i", "7"}},
		{args: []string{"add-query-to-pack", "-p", "lp", "-Q", "pq", "-q", "select 2", "-i", "30"}, wantErr: "local pack"},
		{args: []string{"remove-query-from-pack", "-p", "pk", "-q", "pq"}},
		{args: []string{"remove-query-from-pack", "-p", "missing", "-q", "pq"}, wantErr: "pack missing not found"},
		{args: []string{"remove-pack", "-p", "lp"}},
		{args: []string{"remove-pack", "-p", "missing"}},
	} {
		outDB, errDB := rig.RunDB(append([]string{"env", step.args[0], "-n", "pdb"}, step.args[1:]...)...)
		outAPI, errAPI := rig.RunAPI(append([]string{"env", step.args[0], "-n", "papi"}, step.args[1:]...)...)
		if step.wantErr != "" {
			require.ErrorContains(t, errDB, step.wantErr, step.args)
			require.Error(t, errAPI, step.args)
			require.Equal(t, errDB.Error(), strings.ReplaceAll(errAPI.Error(), "papi", "pdb"), step.args)
		} else {
			require.NoError(t, errDB, step.args)
			require.NoError(t, errAPI, step.args)
		}
		require.Equal(t, outDB, strings.ReplaceAll(outAPI, "papi", "pdb"), step.args)
		require.Equal(t, storedConf(t, rig, "pdb"), storedConf(t, rig, "papi"), step.args)
		for _, name := range []string{"pdb", "papi"} {
			rows := envAuditRows(t, rig, name)
			if step.wantErr != "" {
				require.Empty(t, rows, "%s %v", name, step.args)
				continue
			}
			require.Len(t, rows, 1, "%s %v", name, step.args)
			require.EqualValues(t, auditlog.LogTypeEnvironment, rows[0].LogType, name)
			require.True(t, strings.HasSuffix(rows[0].Line, "performed configuration action: config patch on env "+name), rows[0].Line)
		}
	}
	// The edits did land, and unknown pack keys survived.
	conf := storedConf(t, rig, "pdb")
	require.Contains(t, conf["schedule"], "select 00")
	require.NotContains(t, conf["schedule"], `"q1"`)
	require.Contains(t, conf["options"], "o_int")
	require.Contains(t, conf["packs"], `"custom": true`)
	require.Contains(t, conf["packs"], "select 99")
	require.Contains(t, conf["configuration"], "select 99")
}

// TestEditSectionEmptyAndMalformedStored: an empty or null section is edited
// as an empty one; a non-object or invalid section is an error that leaves the
// stored value untouched; unrelated entries are kept.
func TestEditSectionEmptyAndMalformedStored(t *testing.T) {
	cmds := map[string][]string{
		"schedule": {"add-scheduled-query", "-Q", "new", "-q", "select 1", "-i", "60"},
		"options":  {"add-osquery-option", "-o", "new", "-t", "string", "-s", "x"},
		"packs":    {"add-new-pack", "-p", "new"},
	}
	// One rig: every case sets the section it edits.
	rig := newParityRig(t)
	for _, mode := range []string{"db", "api"} {
		for section, args := range cmds {
			for _, tc := range []struct {
				stored  string
				wantErr bool
				keep    bool
			}{
				{stored: ""},
				{stored: "  "},
				{stored: "{}"},
				{stored: "null"},
				{stored: `{"keep":{"query":"select 0","interval":10}}`, keep: true},
				{stored: `[1,2]`, wantErr: true},
				{stored: `"str"`, wantErr: true},
				{stored: `{bad`, wantErr: true},
			} {
				t.Run(mode+"/"+section+"/"+tc.stored, func(t *testing.T) {
					run := map[string]func(...string) (string, error){"db": rig.RunDB, "api": rig.RunAPI}[mode]
					for _, reset := range []func(string, string) error{rig.Envs.UpdateSchedule, rig.Envs.UpdateOptions, rig.Envs.UpdatePacks} {
						require.NoError(t, reset("dev", "{}"))
					}
					update := map[string]func(string, string) error{"schedule": rig.Envs.UpdateSchedule, "options": rig.Envs.UpdateOptions, "packs": rig.Envs.UpdatePacks}[section]
					require.NoError(t, update("dev", tc.stored))
					before := storedConf(t, rig, "dev")
					var err error
					require.NotPanics(t, func() {
						_, err = run(append([]string{"env", args[0], "-n", "dev"}, args[1:]...)...)
					})
					after := storedConf(t, rig, "dev")
					if tc.wantErr {
						require.ErrorContains(t, err, "error structuring "+section)
						require.Equal(t, before, after, "nothing is written")
						return
					}
					require.NoError(t, err)
					var got map[string]interface{}
					require.NoError(t, json.Unmarshal([]byte(after[section]), &got))
					require.Contains(t, got, "new")
					if tc.keep {
						require.Contains(t, got, "keep")
						require.Len(t, got, 2)
					} else {
						require.Len(t, got, 1)
					}
					for k := range before {
						if k != section && k != "configuration" {
							require.Equal(t, before[k], after[k], "unrelated section %s", k)
						}
					}
				})
			}
		}
	}
}

// TestEnvConfigForbiddenShown: a token without admin access to the target
// environment gets the API's 403 text, and nothing changes.
func TestEnvConfigForbiddenShown(t *testing.T) {
	rig := newParityRig(t)
	prod := rig.SeedEnv("prod")
	dev, err := rig.Envs.Get("dev")
	require.NoError(t, err)
	bob := rig.SeedUser("bob", false)
	require.NoError(t, rig.Users.SetEnvLevel("bob", dev.UUID, users.UserLevel, true))
	carol := rig.SeedUser("carol", false)
	require.NoError(t, rig.Users.SetEnvLevel("carol", prod.UUID, users.AdminLevel, true))
	before := storedConf(t, rig, "dev")
	for _, token := range []string{bob, carol} {
		for _, args := range [][]string{
			{"add-scheduled-query", "-Q", "q", "-q", "select 1", "-i", "60"},
			{"remove-pack", "-p", "x"},
			{"add-posture-queries", "-p", "linux-server"},
		} {
			_, err := rig.RunAPIAs(token, append([]string{"env", args[0], "-n", "dev"}, args[1:]...)...)
			require.ErrorContains(t, err, "403", args)
			require.ErrorContains(t, err, "no access", args)
		}
	}
	require.Equal(t, before, storedConf(t, rig, "dev"))
}

// TestAPIModeConflictingEditIsNotSilent documents that an API-mode edit is
// read-modify-write and NOT atomic: the API only replaces whole sections, so
// a change saved by someone else between the CLI's GET and PATCH is
// overwritten. It is not silent in the sense that every such command says so
// in its help (Description), which this test also pins.
func TestAPIModeConflictingEditIsNotSilent(t *testing.T) {
	rig := newParityRig(t)
	restore := saveCLIGlobals()
	t.Cleanup(restore)
	dbFlag, apiFlag, osctrlAPI = false, true, rig.API
	err := editEnvConfigSection("dev", "schedule", func(current string) (string, error) {
		// A concurrent edit lands after the CLI read the section.
		require.NoError(t, rig.Envs.UpdateSchedule("dev", `{"concurrent":{"query":"select 1","interval":1}}`))
		return environments.AddScheduleQueries(current, environments.ScheduleConf{"mine": {Query: "select 2", Interval: "2"}})
	})
	require.NoError(t, err)
	schedule := storedConf(t, rig, "dev")["schedule"]
	require.Contains(t, schedule, "mine")
	require.NotContains(t, schedule, "concurrent", "last writer wins: the concurrent edit is lost")

	var env *cli.Command
	for _, c := range commands {
		if c.Name == "environment" {
			env = c
		}
	}
	require.NotNil(t, env)
	for _, name := range []string{"add-scheduled-query", "add-posture-queries", "remove-scheduled-query", "add-osquery-option", "remove-osquery-option", "add-new-pack", "add-local-pack", "remove-pack", "add-query-to-pack", "remove-query-from-pack"} {
		c := env.Command(name)
		require.NotNil(t, c, name)
		require.Contains(t, c.Description, "not atomic", name)
	}
}

func TestEditEnvConfigSectionRejectsNonJSONAndUnknownSection(t *testing.T) {
	rig := newParityRig(t)
	restore := saveCLIGlobals()
	t.Cleanup(restore)
	before := storedConf(t, rig, "dev")
	for _, mode := range []struct {
		db, api bool
		client  *apiclient.OsctrlAPI
		mgr     *environments.EnvManager
	}{{db: true, mgr: rig.Envs}, {api: true, client: rig.API}} {
		dbFlag, apiFlag, osctrlAPI, envs = mode.db, mode.api, mode.client, mode.mgr
		require.ErrorContains(t, editEnvConfigSection("dev", "schedule", func(string) (string, error) { return "{bad", nil }), "not valid JSON")
		require.ErrorContains(t, editEnvConfigSection("dev", "flags", func(c string) (string, error) { return c, nil }), "unknown configuration section")
	}
	require.Equal(t, before, storedConf(t, rig, "dev"))
}
