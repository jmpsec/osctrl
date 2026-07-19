package environments

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddScheduleConfQueriesMergesMultipleQueries(t *testing.T) {
	db := setupTestDB(t)
	envs := CreateEnvironment(db)

	env := envs.Empty("dev", "dev.example.com")
	env.Schedule = `{"existing":{"query":"SELECT 1;","interval":60}}`
	require.NoError(t, envs.Create(&env))

	err := envs.AddScheduleConfQueries(env.Name, ScheduleConf{
		"osctrl:posture:packages": {
			Query:    "SELECT name FROM deb_packages;",
			Interval: json.Number("86400"),
			Platform: "linux",
			Snapshot: true,
		},
		"osctrl:posture:users": {
			Query:    "SELECT username FROM users;",
			Interval: json.Number("86400"),
			Snapshot: true,
		},
	})
	require.NoError(t, err)

	updated, err := envs.Get(env.Name)
	require.NoError(t, err)

	schedule, err := envs.GenStructSchedule([]byte(updated.Schedule))
	require.NoError(t, err)
	require.Contains(t, schedule, "existing")
	require.Contains(t, schedule, "osctrl:posture:packages")
	require.Contains(t, schedule, "osctrl:posture:users")
	require.Equal(t, "linux", schedule["osctrl:posture:packages"].Platform)
	require.True(t, schedule["osctrl:posture:packages"].Snapshot)
}
