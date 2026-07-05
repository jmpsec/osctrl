package handlers

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSyncCompletedCarveQueryCompletesParentWhenAllTargetsFinish(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	queryManager := queries.CreateQueries(db)
	carveManager := carves.CreateFileCarves(db, "", nil)

	query := queries.DistributedQuery{
		Name:          "carve_test_1",
		Query:         "SELECT * FROM carves WHERE carve=1 AND path = '/tmp/file';",
		Type:          queries.CarveQueryType,
		Active:        true,
		Expected:      2,
		EnvironmentID: 1,
		Expiration:    time.Now().Add(time.Hour),
	}
	require.NoError(t, queryManager.Create(&query))

	files := []carves.CarvedFile{
		{
			CarveID:       "carve-1",
			RequestID:     "req-1",
			SessionID:     "session-1",
			QueryName:     query.Name,
			UUID:          "node-1",
			NodeID:        1,
			Environment:   "dev",
			Path:          "/tmp/file",
			Status:        carves.StatusCompleted,
			EnvironmentID: query.EnvironmentID,
		},
		{
			CarveID:       "carve-2",
			RequestID:     "req-2",
			SessionID:     "session-2",
			QueryName:     query.Name,
			UUID:          "node-2",
			NodeID:        2,
			Environment:   "dev",
			Path:          "/tmp/file",
			Status:        carves.StatusCompleted,
			EnvironmentID: query.EnvironmentID,
		},
	}
	for _, file := range files {
		require.NoError(t, carveManager.CreateCarve(file))
	}

	h := &HandlersTLS{
		Queries: queryManager,
		Carves:  carveManager,
	}

	require.NoError(t, h.syncCompletedCarveQuery("session-1"))

	updated, err := queryManager.Get(query.Name, query.EnvironmentID)
	require.NoError(t, err)
	assert.True(t, updated.Completed)
	assert.False(t, updated.Active)
}
