package queries_test

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
)

// Cancelling node-queries lowers Expected and completes a query that has
// nothing left pending, so cancelled work never shows as stuck.
func TestCancelNodeQueries(t *testing.T) {
	db := testDB(t)
	q, _, query := setupTestData(t, db)
	require.NoError(t, db.Model(query).Update("expected", 3).Error)
	require.NoError(t, q.CreateNodeQueries([]uint{1, 2, 3}, query.ID))
	carve := &queries.DistributedQuery{ID: 2, Name: "carve_1", Type: queries.CarveQueryType, Active: true, EnvironmentID: 1, Expected: 2}
	require.NoError(t, db.Create(carve).Error)
	require.NoError(t, q.CreateNodeQueries([]uint{1, 2}, carve.ID))

	idsOf := func(queryID uint, nodeIDs ...uint) []uint {
		var ids []uint
		require.NoError(t, db.Model(&queries.NodeQuery{}).Where("query_id = ? AND node_id IN ?", queryID, nodeIDs).Pluck("id", &ids).Error)
		return ids
	}
	reload := func(id uint) queries.DistributedQuery {
		var got queries.DistributedQuery
		require.NoError(t, db.First(&got, id).Error)
		return got
	}

	// Node 1 already answered; cancelling the last two pending targets
	// completes the query, with Expected down to the one real answer.
	require.NoError(t, q.UpdateQueryStatus("test_query", 1, 0))
	require.NoError(t, q.CancelNodeQueries(idsOf(query.ID, 2, 3)))
	got := reload(query.ID)
	require.Equal(t, 1, got.Expected)
	require.True(t, got.Completed)
	require.False(t, got.Active)

	// A carve with a target left pending only loses the cancelled target.
	require.NoError(t, q.CancelNodeQueries(idsOf(carve.ID, 2)))
	gotCarve := reload(carve.ID)
	require.Equal(t, 1, gotCarve.Expected)
	require.True(t, gotCarve.Active)
	// Once nothing is left to arrive, the carve completes too.
	require.NoError(t, q.CancelNodeQueries(idsOf(carve.ID, 1)))
	gotCarve = reload(carve.ID)
	require.Equal(t, 0, gotCarve.Expected)
	require.True(t, gotCarve.Completed)

	require.NoError(t, q.CancelNodeQueries(nil))
}
