package carves

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type carveEventRecorder struct{ hints []events.Hint }

func (r *carveEventRecorder) Publish(h events.Hint) { r.hints = append(r.hints, h) }

func TestCarveNotificationsFollowSuccessfulPersistence(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	c := CreateFileCarves(db, config.CarverDB, nil)
	recorder := &carveEventRecorder{}
	c.Events = recorder
	file := CarvedFile{EnvironmentID: 1, QueryName: "carve-query", SessionID: "session"}
	require.NoError(t, c.CreateCarve(file))
	require.NoError(t, c.CompleteBlock(file.SessionID))
	require.NoError(t, c.ChangeStatus(StatusCompleted, file.SessionID))
	stored, err := c.GetBySession(file.SessionID)
	require.NoError(t, err)
	require.Equal(t, 1, stored.CompletedBlocks)
	require.Equal(t, StatusCompleted, stored.Status)
	require.Equal(t, []events.Hint{
		{EnvironmentID: 1, Topic: events.Carves, Name: file.QueryName, Change: events.ChangeFiles},
		{EnvironmentID: 1, Topic: events.Carves, Name: file.QueryName, Change: events.ChangeFiles},
	}, recorder.hints)
	recorder.hints = nil
	require.NoError(t, db.Migrator().DropTable(&CarvedFile{}))
	require.Error(t, c.CompleteBlock(file.SessionID))
	require.Error(t, c.ChangeStatus(StatusCompleted, file.SessionID))
	require.Empty(t, recorder.hints, "failed writes must not emit notifications")
}
