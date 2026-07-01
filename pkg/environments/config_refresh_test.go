package environments

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshConfigurationRecomposesAfterPartUpdate locks the contract the
// environment-config PATCH handler relies on: UpdateSchedule (and the other
// Update* part writers) only persist their own column — they do NOT recompose
// the assembled `configuration` blob that GET .../configuration/assembled
// returns and that agents receive on /config refresh. RefreshConfiguration
// is what folds the parts back together. Without the handler calling it, a
// schedule edit saved from the SPA's Configuration → Schedule tab never shows
// up on the enroll page's Configuration tab.
func TestRefreshConfigurationRecomposesAfterPartUpdate(t *testing.T) {
	db := setupTestDB(t)
	envs := CreateEnvironment(db)

	env := envs.Empty("dev", "dev.example.com")
	require.NoError(t, envs.Create(&env))

	schedule := `{"uptime":{"query":"SELECT * FROM uptime;","interval":60}}`
	require.NoError(t, envs.UpdateSchedule(env.Name, schedule))

	// The bug: the part is saved, but the composed blob is still the empty
	// placeholder until RefreshConfiguration runs.
	before, err := envs.Get(env.Name)
	require.NoError(t, err)
	assert.Equal(t, "{}", before.Configuration, "UpdateSchedule must not recompose configuration on its own")

	// The fix: RefreshConfiguration folds the updated schedule (and the other
	// parts) into the composed blob.
	require.NoError(t, envs.RefreshConfiguration(env.Name))

	after, err := envs.Get(env.Name)
	require.NoError(t, err)
	assert.NotEqual(t, "{}", after.Configuration, "RefreshConfiguration should recompose the blob")
	assert.True(t, strings.Contains(after.Configuration, "uptime"),
		"assembled configuration should contain the scheduled query, got %s", after.Configuration)
	assert.True(t, strings.Contains(after.Configuration, "SELECT * FROM uptime;"),
		"assembled configuration should contain the query SQL, got %s", after.Configuration)
}
