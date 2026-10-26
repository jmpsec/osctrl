package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestCheckMode(t *testing.T) {
	const (
		dbOnly  = "this command works with the local database only: run it with --db (and -D <db config file>)"
		apiOnly = "this command works through the API only: run it without --db"
		apiOff  = "this command works through the API only: enable --api"
		none    = "no connection mode selected: use --db (with -D <db config file>) or --api"
	)
	tests := []struct {
		name            string
		mode            cliMode
		dbFlag, apiFlag bool
		errMsg          string
	}{
		{"any db+api", modeAny, true, true, ""},
		{"any db only", modeAny, true, false, ""},
		{"any api only", modeAny, false, true, ""},
		{"any none", modeAny, false, false, none},
		{"db-only db+api", modeDB, true, true, ""},
		{"db-only db", modeDB, true, false, ""},
		{"db-only api", modeDB, false, true, dbOnly},
		{"db-only none", modeDB, false, false, dbOnly},
		{"api-only api", modeAPI, false, true, ""},
		{"api-only db+api", modeAPI, true, true, apiOnly},
		{"api-only db", modeAPI, true, false, apiOnly},
		{"api-only none", modeAPI, false, false, apiOff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMode(tt.mode, tt.dbFlag, tt.apiFlag)
			if tt.errMsg == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.errMsg)
		})
	}
}

// saveModeGlobals restores the globals the wrapper reads or writes.
func saveModeGlobals(t *testing.T) {
	oldDB, oldAPI, oldAPIClient, oldFile, oldFormat, oldVerbose := dbFlag, apiFlag, osctrlAPI, dbConfigFile, formatFlag, verboseFlag
	t.Cleanup(func() {
		dbFlag, apiFlag, osctrlAPI, dbConfigFile, formatFlag, verboseFlag = oldDB, oldAPI, oldAPIClient, oldFile, oldFormat, oldVerbose
	})
	formatFlag, verboseFlag = jsonFormat, false
}

func TestWrapperRejectsWrongModeWithoutPanic(t *testing.T) {
	saveModeGlobals(t)
	called := false
	stub := func(context.Context, *cli.Command) error { called = true; return nil }
	run := func(a func(context.Context, *cli.Command) error) error {
		return (&cli.Command{Name: "x", Action: a}).Run(context.Background(), []string{"x"})
	}
	// DB-only action in API mode (the default): no managers, no panic.
	dbFlag, apiFlag = false, true
	require.NotPanics(t, func() {
		require.ErrorContains(t, run(cliWrapperDB(stub)), "with the local database only")
		// A real DB-only action, with every manager nil.
		require.ErrorContains(t, run(cliWrapperDB(listConfiguration)), "with the local database only")
	})
	// API-only action with --db: rejected before DB init (no config file set).
	dbFlag, apiFlag, dbConfigFile = true, true, ""
	require.NotPanics(t, func() {
		require.ErrorContains(t, run(cliWrapperAPI(alertRulesList)), "through the API only")
	})
	require.False(t, called)
}

func TestWrapperNoModeSelectedFails(t *testing.T) {
	saveModeGlobals(t)
	dbFlag, apiFlag = false, false
	called := false
	stub := func(context.Context, *cli.Command) error { called = true; return nil }
	run := func(a cli.ActionFunc) error {
		return (&cli.Command{Name: "x", Action: a}).Run(context.Background(), []string{"x"})
	}
	require.ErrorContains(t, run(cliWrapperAPI(alertRulesList)), "enable --api")
	require.ErrorContains(t, run(cliWrapper(stub)), "no connection mode selected")
	require.False(t, called)
}

func TestWrapperDBWinsOverAPI(t *testing.T) {
	saveModeGlobals(t)
	oldMgrs := [...]any{db, adminUsers, envs, settingsmgr, nodesmgr, queriesmgr, filecarves, tagsmgr, auditlogsmgr}
	t.Cleanup(func() {
		db, adminUsers, envs, settingsmgr, nodesmgr, queriesmgr, filecarves, tagsmgr, auditlogsmgr =
			oldMgrs[0].(*backend.DBManager), oldMgrs[1].(*users.UserManager), oldMgrs[2].(*environments.EnvManager),
			oldMgrs[3].(*settings.Settings), oldMgrs[4].(*nodes.NodeManager), oldMgrs[5].(*queries.Queries),
			oldMgrs[6].(*carves.Carves), oldMgrs[7].(*tags.TagManager), oldMgrs[8].(*auditlog.AuditLogManager)
	})
	dir := t.TempDir()
	dbConfigFile = filepath.Join(dir, "db.yml")
	require.NoError(t, os.WriteFile(dbConfigFile, []byte("db:\n  type: sqlite\n  filePath: "+filepath.Join(dir, "osctrl.db")+"\n"), 0o600))
	dbFlag, apiFlag, osctrlAPI = true, true, nil
	sawAPI := true
	stub := func(context.Context, *cli.Command) error { sawAPI = apiFlag; return nil }
	require.NoError(t, (&cli.Command{Name: "x", Action: cliWrapper(stub)}).Run(context.Background(), []string{"x"}))
	require.False(t, sawAPI, "with --db the action must never see apiFlag")
}

// GenerateFlags does not use its receiver today; in API mode envs is nil, so
// pin that it keeps working without the database manager.
func TestGenFlagsEnvironmentAPIModeNoPanic(t *testing.T) {
	saveModeGlobals(t)
	oldEnvs := envs
	t.Cleanup(func() { envs = oldEnvs })
	envs = nil
	require.NotPanics(t, func() {
		_, err := envs.GenerateFlags(environments.TLSEnvironment{}, "", "", config.YAMLConfigurationOsquery{Config: true})
		require.NoError(t, err)
	})
}
