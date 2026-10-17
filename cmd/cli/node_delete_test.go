package main

import (
	"context"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupNodeDelete wires the CLI's DB-mode globals to a fresh database holding
// node NODE-A with a config override, a flags override and an osctrld status.
func setupNodeDelete(t *testing.T) (*nodeconfig.Manager, *gorm.DB) {
	t.Helper()
	oldNodes, oldAudit, oldDB, oldSilent := nodesmgr, auditlogsmgr, dbFlag, silentFlag
	t.Cleanup(func() { nodesmgr, auditlogsmgr, dbFlag, silentFlag = oldNodes, oldAudit, oldDB, oldSilent })
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	nodesmgr = nodes.CreateNodes(db)
	auditlogsmgr, err = auditlog.CreateAuditLogManager(db, "osctrl-cli", true)
	require.NoError(t, err)
	dbFlag, silentFlag = true, true
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "NODE-A", EnvironmentID: 1, Environment: "a"}).Error)
	mgr, err := nodeconfig.NewManager(db, nil)
	require.NoError(t, err)
	_, err = mgr.Set(context.Background(), nodeconfig.Override{NodeUUID: "NODE-A", EnvironmentID: 1, Config: `{"options":{"verbose":true}}`})
	require.NoError(t, err)
	fm, err := nodeconfig.NewFlagsManager(db, nil)
	require.NoError(t, err)
	_, err = fm.Set(context.Background(), nodeconfig.FlagsOverride{NodeUUID: "NODE-A", EnvironmentID: 1, Flags: "--verbose=true"})
	require.NoError(t, err)
	require.NoError(t, fm.RecordFetch("NODE-A", 1, time.Now(), nil))
	return mgr, db
}

// requireNodeRowsGone checks the node's config override, flags override and
// osctrld status are hard-deleted.
func requireNodeRowsGone(t *testing.T, mgr *nodeconfig.Manager, db *gorm.DB) {
	t.Helper()
	o, err := mgr.Get("NODE-A")
	require.NoError(t, err)
	require.Nil(t, o)
	for _, model := range []any{&nodeconfig.FlagsOverride{}, &nodeconfig.OsctrldStatus{}} {
		var n int64
		require.NoError(t, db.Unscoped().Model(model).Count(&n).Error)
		require.Zero(t, n, "%T", model)
	}
}

func TestCLIDeleteNodeRemovesOverride(t *testing.T) {
	mgr, db := setupNodeDelete(t)
	cmd := &cli.Command{
		Name:   "delete",
		Flags:  []cli.Flag{&cli.StringFlag{Name: "uuid"}, &cli.StringFlag{Name: "env"}},
		Action: deleteNode,
	}
	require.NoError(t, cmd.Run(context.Background(), []string{"delete", "--uuid", "node-a", "--env", "a"}))
	requireNodeRowsGone(t, mgr, db)
}

func TestShellDBStoreDeleteNodeRemovesOverride(t *testing.T) {
	mgr, db := setupNodeDelete(t)
	require.NoError(t, (&dbStore{}).DeleteNode("a", "node-a"))
	requireNodeRowsGone(t, mgr, db)
}
