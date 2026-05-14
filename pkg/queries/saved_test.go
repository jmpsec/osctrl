package queries_test

import (
	"errors"
	"testing"

	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestSavedQuerySortableColumns asserts the allowlist is closed and maps each
// API-facing key onto an actual storage column. The map is consulted from
// GetSavedByEnvPaged before any ORDER BY expression is built; if this drift
// allowlist drifts the API stops accepting that sort key (which is the right
// behavior — we don't want to add a column the package can't translate).
func TestSavedQuerySortableColumns(t *testing.T) {
	want := map[string]string{
		"name":    "name",
		"creator": "creator",
		"created": "created_at",
		"updated": "updated_at",
	}
	assert.Equal(t, want, queries.SavedQuerySortableColumns)
}

func TestSavedQueryCRUD(t *testing.T) {
	db := testDB(t)
	q := queries.CreateQueries(db)

	// Create
	require.NoError(t, q.CreateSaved("first", "SELECT 1", "alice", 1))
	require.True(t, q.SavedExists("first", 1))
	require.False(t, q.SavedExists("first", 2)) // different env, still false

	// Duplicate in same env detected via SavedExists (handler enforces 409)
	require.True(t, q.SavedExists("first", 1))

	// GetSavedByEnv returns the row regardless of creator
	got, err := q.GetSavedByEnv("first", 1)
	require.NoError(t, err)
	assert.Equal(t, "first", got.Name)
	assert.Equal(t, "alice", got.Creator)
	assert.Equal(t, "SELECT 1", got.Query)

	// GetSaved (creator-scoped) — same creator wins
	got2, err := q.GetSaved("first", "alice", 1)
	require.NoError(t, err)
	assert.Equal(t, got.ID, got2.ID)

	// GetSaved with the wrong creator returns ErrRecordNotFound (not a zero row)
	_, err = q.GetSaved("first", "bob", 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))

	// Update preserves creator
	require.NoError(t, q.UpdateSaved("first", "SELECT 2", 1))
	updated, err := q.GetSavedByEnv("first", 1)
	require.NoError(t, err)
	assert.Equal(t, "SELECT 2", updated.Query)
	assert.Equal(t, "alice", updated.Creator, "update must not overwrite creator")

	// Delete by env
	require.NoError(t, q.DeleteSavedByEnv("first", 1))
	assert.False(t, q.SavedExists("first", 1))

	// Deleting again surfaces ErrRecordNotFound
	err = q.DeleteSavedByEnv("first", 1)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
}

func TestGetSavedByEnvPaged(t *testing.T) {
	db := testDB(t)
	q := queries.CreateQueries(db)

	// Seed across two envs to verify env scoping
	require.NoError(t, q.CreateSaved("alpha", "SELECT a", "alice", 1))
	require.NoError(t, q.CreateSaved("beta", "SELECT b", "alice", 1))
	require.NoError(t, q.CreateSaved("gamma", "SELECT c", "bob", 1))
	require.NoError(t, q.CreateSaved("other_env", "SELECT z", "alice", 2))

	// Default sort = created_at DESC, env 1
	page, err := q.GetSavedByEnvPaged(1, "", 0, 0, "", false)
	require.NoError(t, err)
	assert.Equal(t, int64(3), page.TotalItems, "env scoping leaks if this is != 3")
	require.Len(t, page.Items, 3)
	assert.Equal(t, "gamma", page.Items[0].Name, "newest first by default")

	// Search narrows to one row
	page, err = q.GetSavedByEnvPaged(1, "alph", 0, 0, "", false)
	require.NoError(t, err)
	assert.Equal(t, int64(1), page.TotalItems)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "alpha", page.Items[0].Name)

	// Sort by name asc
	page, err = q.GetSavedByEnvPaged(1, "", 0, 0, "name", false)
	require.NoError(t, err)
	require.Len(t, page.Items, 3)
	assert.Equal(t, []string{"alpha", "beta", "gamma"}, []string{
		page.Items[0].Name, page.Items[1].Name, page.Items[2].Name,
	})

	// Pagination — page_size 2, page 1 of 2
	page, err = q.GetSavedByEnvPaged(1, "", 1, 2, "name", false)
	require.NoError(t, err)
	require.Len(t, page.Items, 2)
	assert.Equal(t, []string{"alpha", "beta"}, []string{
		page.Items[0].Name, page.Items[1].Name,
	})
	assert.Equal(t, int64(3), page.TotalItems)

	// Pagination — page 2
	page, err = q.GetSavedByEnvPaged(1, "", 2, 2, "name", false)
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "gamma", page.Items[0].Name)

	// Unknown sort key falls back to created_at DESC
	page, err = q.GetSavedByEnvPaged(1, "", 0, 0, "DROP TABLE", false)
	require.NoError(t, err, "unknown sort key must fall back, never inject")
	require.Len(t, page.Items, 3)
}
