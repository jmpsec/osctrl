package queries

import (
	"fmt"
	"strings"

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
			switch kind {
			case ConsoleQueryType:
				query.ExtraData = `{"session_id":7,"command_id":8}`
			case FileExplorerQueryType:
				query.ExtraData = `{"session_id":9,"request_id":10}`
			}
			require.NoError(t, q.Create(&query))
			require.NoError(t, q.CreateNodeQueries([]uint{1}, query.ID))
			require.NoError(t, q.UpdateQueryStatus(query.Name, 1, 0))
			switch kind {
			case StandardQueryType, CarveQueryType:
				require.Len(t, recorder.hints, 1)
				require.Equal(t, query.Name, recorder.hints[0].Name)
				require.Equal(t, uint(1), recorder.hints[0].EnvironmentID)
				require.Equal(t, events.ChangeMetadata, recorder.hints[0].Change)
			case ConsoleQueryType:
				require.Equal(t, []events.Hint{{EnvironmentID: 1, Topic: events.Console, Name: query.Name, Change: events.ChangeMetadata, SessionID: 7, ResourceID: 8}}, recorder.hints)
			case FileExplorerQueryType:
				require.Equal(t, []events.Hint{{EnvironmentID: 1, Topic: events.FileExplorer, Name: query.Name, Change: events.ChangeMetadata, SessionID: 9, ResourceID: 10}}, recorder.hints)
			default:
				require.Empty(t, recorder.hints)
			}
			recorder.hints = nil
			q.NotifyResults(query.Name, 1)
			if kind == StandardQueryType || kind == CarveQueryType || kind == ConsoleQueryType || kind == FileExplorerQueryType {
				require.Len(t, recorder.hints, 1)
				require.Equal(t, events.ChangeResults, recorder.hints[0].Change)
			} else {
				require.Empty(t, recorder.hints)
			}
			recorder.hints = nil
			q.NotifyChange(query.Name, 2)
			require.Empty(t, recorder.hints, "wrong environment must never produce a hint")
		})
	}
}

func TestInternalQueryEventsRequireSessionExtraData(t *testing.T) {
	for _, kind := range []string{ConsoleQueryType, FileExplorerQueryType} {
		t.Run(kind, func(t *testing.T) {
			db := setupTestDB(t)
			q := CreateQueries(db)
			recorder := &eventRecorder{}
			q.Events = recorder
			query := DistributedQuery{Name: "missing-extra-" + strings.ReplaceAll(kind, "_", "-"), EnvironmentID: 1, Type: kind, Active: true, ExtraData: fmt.Sprintf(`{"session_id":1,"%s":0}`, map[string]string{ConsoleQueryType: "command_id", FileExplorerQueryType: "request_id"}[kind])}
			require.NoError(t, q.Create(&query))
			q.NotifyResults(query.Name, 1)
			require.Empty(t, recorder.hints)
		})
	}
}
