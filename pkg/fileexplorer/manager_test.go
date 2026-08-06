package fileexplorer_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/fileexplorer"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupFileExplorerManager(t *testing.T) (*gorm.DB, *fileexplorer.Manager, environments.TLSEnvironment, nodes.OsqueryNode) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&environments.TLSEnvironment{}, &nodes.OsqueryNode{}, &logging.OsqueryQueryData{}))

	env := environments.TLSEnvironment{UUID: "env-uuid", Name: "env"}
	require.NoError(t, db.Create(&env).Error)
	node := nodes.OsqueryNode{UUID: "NODE-UUID", Platform: "linux", EnvironmentID: env.ID, Environment: env.UUID}
	require.NoError(t, db.Create(&node).Error)

	queryManager := queries.CreateQueries(db)
	return db, fileexplorer.NewManager(db, queryManager), env, node
}

func TestCreateSessionDefaultsRootByPlatform(t *testing.T) {
	_, manager, env, node := setupFileExplorerManager(t)
	node.Platform = "windows"

	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	require.True(t, session.Active)
	require.Equal(t, node.UUID, session.NodeUUID)
	require.Equal(t, `C:\`, session.Root)
}

func TestListDirectoryCreatesHiddenFileExplorerQuery(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	request, err := manager.ListDirectory(session.ID, "/etc", 10*time.Second)
	require.NoError(t, err)
	require.Equal(t, fileexplorer.ActionList, request.Action)
	require.Equal(t, fileexplorer.StatusQueued, request.Status)
	require.Equal(t, "/etc", request.Path)
	require.Contains(t, request.TranslatedSQL, "from file")
	require.Contains(t, request.TranslatedSQL, "directory = '/etc'")

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", request.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.FileExplorerQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
	require.True(t, distributed.Active)
	require.Equal(t, uint(1), uint(distributed.Expected))
	require.Equal(t, env.ID, distributed.EnvironmentID)

	var nodeQuery queries.NodeQuery
	require.NoError(t, db.Where("query_id = ?", distributed.ID).First(&nodeQuery).Error)
	require.Equal(t, node.ID, nodeQuery.NodeID)
}

func TestStatPathCreatesHiddenFileExplorerQuery(t *testing.T) {
	_, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	request, err := manager.StatPath(session.ID, "/etc/hosts", 10*time.Second)
	require.NoError(t, err)
	require.Equal(t, fileexplorer.ActionStat, request.Action)
	require.Equal(t, "/etc/hosts", request.Path)
	require.Contains(t, request.TranslatedSQL, "path = '/etc/hosts'")
}

func TestSubmitPrimingRequestCreatesHiddenFileExplorerQuery(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	priming, err := manager.SubmitPrimingRequest(session.ID, time.Minute)
	require.NoError(t, err)
	require.True(t, priming.Priming)
	require.Equal(t, fileexplorer.ActionPriming, priming.Action)
	require.Equal(t, fileexplorer.StatusQueued, priming.Status)
	require.NotEmpty(t, priming.DistributedQueryName)
	require.Equal(t, fileexplorer.PrimingMetadataSQL, priming.TranslatedSQL)

	var distributed queries.DistributedQuery
	require.NoError(t, db.Where("name = ?", priming.DistributedQueryName).First(&distributed).Error)
	require.Equal(t, queries.FileExplorerQueryType, distributed.Type)
	require.True(t, distributed.Hidden)
	require.True(t, distributed.Active)

	delivered, accelerate, err := manager.Queries.NodeQueries(node)
	require.NoError(t, err)
	require.True(t, accelerate)
	require.Equal(t, fileexplorer.PrimingMetadataSQL, delivered[priming.DistributedQueryName])
}

func TestPrimingRequestDoesNotCountTowardsPendingCap(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)

	_, err = manager.SubmitPrimingRequest(session.ID, time.Minute)
	require.NoError(t, err)

	// A priming request is queued but should not count against the
	// per-session pending cap, so a real list request must still be
	// accepted.
	_, err = manager.ListDirectory(session.ID, "/etc", 10*time.Second)
	require.NoError(t, err)

	var queuedNonPriming int64
	require.NoError(t, db.Model(&fileexplorer.Request{}).
		Where("session_id = ? AND status = ? AND priming = ?", session.ID, fileexplorer.StatusQueued, false).
		Count(&queuedNonPriming).Error)
	require.Equal(t, int64(1), queuedNonPriming)
}

func TestRequestMetadataRowsReturnOsqueryInfoRows(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	priming, err := manager.SubmitPrimingRequest(session.ID, time.Minute)
	require.NoError(t, err)

	result, err := json.Marshal([]map[string]string{{"version": "5.13.1", "build_platform": "linux"}})
	require.NoError(t, err)
	wrapped, err := json.Marshal(types.QueryWriteData{
		Name:   priming.DistributedQueryName,
		Result: result,
		Status: 0,
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{
		UUID:        node.UUID,
		Environment: env.UUID,
		Name:        priming.DistributedQueryName,
		Data:        string(wrapped),
		Status:      0,
	}).Error)
	require.NoError(t, markFileExplorerNodeQueryStatus(db, priming.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	rows, err := manager.RequestMetadataRows(priming.ID)
	require.NoError(t, err)
	require.Equal(t, []map[string]any{{"version": "5.13.1", "build_platform": "linux"}}, rows)
}

func TestRefreshRequestStatusFromNodeQuery(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	request, err := manager.ListDirectory(session.ID, "/etc", 10*time.Second)
	require.NoError(t, err)

	require.NoError(t, markFileExplorerNodeQueryStatus(db, request.DistributedQueryName, queries.DistributedQueryStatusCompleted))
	got, err := manager.RefreshRequestStatus(request.ID)
	require.NoError(t, err)
	require.Equal(t, fileexplorer.StatusCompleted, got.Status)
	require.NotNil(t, got.CompletedAt)
}

func TestRequestResultsDecodeStoredQueryWriteData(t *testing.T) {
	db, manager, env, node := setupFileExplorerManager(t)
	session, err := manager.CreateSession(env, node, "alice")
	require.NoError(t, err)
	request, err := manager.ListDirectory(session.ID, "/etc", 10*time.Second)
	require.NoError(t, err)

	result, err := json.Marshal([]map[string]any{{
		"path":      "/etc/hosts",
		"filename":  "hosts",
		"directory": "/etc",
		"type":      "regular",
		"size":      123,
		"mode":      "0644",
	}})
	require.NoError(t, err)
	wrapped, err := json.Marshal(types.QueryWriteData{
		Name:   request.DistributedQueryName,
		Result: result,
		Status: 0,
	})
	require.NoError(t, err)
	require.NoError(t, db.Create(&logging.OsqueryQueryData{
		UUID:        node.UUID,
		Environment: env.UUID,
		Name:        request.DistributedQueryName,
		Data:        string(wrapped),
		Status:      0,
	}).Error)
	require.NoError(t, markFileExplorerNodeQueryStatus(db, request.DistributedQueryName, queries.DistributedQueryStatusCompleted))

	entries, err := manager.RequestResults(request.ID)
	require.NoError(t, err)
	require.Equal(t, []fileexplorer.Entry{{
		Path:      "/etc/hosts",
		Filename:  "hosts",
		Directory: "/etc",
		Type:      "regular",
		Size:      123,
		Mode:      "0644",
	}}, entries)
}

func markFileExplorerNodeQueryStatus(db *gorm.DB, queryName, status string) error {
	var distributed queries.DistributedQuery
	if err := db.Where("name = ?", queryName).First(&distributed).Error; err != nil {
		return err
	}
	return db.Model(&queries.NodeQuery{}).
		Where("query_id = ?", distributed.ID).
		Update("status", status).Error
}
