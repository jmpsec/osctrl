package handlers

import (
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCreateQueryCarveWithoutTargetsIncludesAllEnvironmentNodes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	envs := environments.CreateEnvironment(db)
	nodeManager := nodes.CreateNodes(db)

	env := envs.Empty("dev", "dev.example.com")
	require.NoError(t, envs.Create(&env))

	now := time.Now()
	fixtures := []nodes.OsqueryNode{
		{
			UUID:          "NODE-1",
			Environment:   env.Name,
			EnvironmentID: env.ID,
			LastSeen:      now,
		},
		{
			UUID:          "NODE-2",
			Environment:   env.Name,
			EnvironmentID: env.ID,
			LastSeen:      now.Add(-72 * time.Hour),
		},
		{
			UUID:          "NODE-3",
			Environment:   "other",
			EnvironmentID: env.ID + 1,
			LastSeen:      now,
		},
	}
	for _, node := range fixtures {
		require.NoError(t, db.Create(&node).Error)
	}

	targetNodesID, err := CreateQueryCarve(
		ProcessingQuery{
			EnvID:         env.ID,
			InactiveHours: 24,
		},
		Managers{
			Envs:  envs,
			Nodes: nodeManager,
		},
		queries.DistributedQuery{},
	)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{1, 2}, targetNodesID)
}
