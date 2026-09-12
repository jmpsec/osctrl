package queries

import (
	"github.com/jmpsec/osctrl/pkg/events"
	"github.com/stretchr/testify/require"
	"testing"
)

type eventRecorder struct{ hints []events.Hint }

func (r *eventRecorder) Publish(h events.Hint) { r.hints = append(r.hints, h) }

func TestQueryEventsExcludeInteractiveAndHiddenTypes(t *testing.T) {
	for _, kind := range []string{StandardQueryType, CarveQueryType, ConsoleQueryType, FileExplorerQueryType, MetadataQueryType} {
		t.Run(kind, func(t *testing.T) {
			db := setupTestDB(t)
			q := CreateQueries(db)
			recorder := &eventRecorder{}
			q.Events = recorder
			query := DistributedQuery{Name: "events-" + kind, EnvironmentID: 1, Type: kind, Active: true}
			require.NoError(t, q.Create(&query))
			require.NoError(t, q.CreateNodeQueries([]uint{1}, query.ID))
			require.NoError(t, q.UpdateQueryStatus(query.Name, 1, 0))
			if kind == StandardQueryType || kind == CarveQueryType {
				require.Len(t, recorder.hints, 1)
				require.Equal(t, query.Name, recorder.hints[0].Name)
				require.Equal(t, uint(1), recorder.hints[0].EnvironmentID)
				require.Equal(t, events.ChangeMetadata, recorder.hints[0].Change)
			} else {
				require.Empty(t, recorder.hints)
			}
			recorder.hints = nil
			q.NotifyChange(query.Name, 2)
			require.Empty(t, recorder.hints, "wrong environment must never produce a hint")
		})
	}
}
