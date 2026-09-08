package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCreateQueryCarveEnvironmentThresholds(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	manager := Managers{Envs: environments.CreateEnvironment(db), Nodes: nodes.CreateNodes(db), Settings: settings.NewSettings(db)}
	require.NoError(t, manager.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, 0))
	var fixtures []nodes.OsqueryNode
	var envUUIDs []string
	for i, name := range []string{"short", "long", "inherited"} {
		env := manager.Envs.Empty(name, name+".example.com")
		require.NoError(t, manager.Envs.Create(&env))
		envUUIDs = append(envUUIDs, env.UUID)
		if i < 2 {
			require.NoError(t, manager.Settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, []int64{2, 168}[i], env.ID))
		}
		node := nodes.OsqueryNode{UUID: strings.ToUpper(name), Hostname: name, Platform: "linux", Environment: name, EnvironmentID: env.ID, LastSeen: time.Now().Add(-48 * time.Hour)}
		require.NoError(t, db.Create(&node).Error)
		fixtures = append(fixtures, node)
	}
	for _, tc := range []struct {
		name string
		data ProcessingQuery
		want []uint
	}{
		{"environments", ProcessingQuery{EnvID: fixtures[0].EnvironmentID, Envs: []string{"short", "long", "inherited"}}, []uint{fixtures[1].ID}},
		{"environment UUIDs", ProcessingQuery{EnvID: fixtures[0].EnvironmentID, Envs: envUUIDs}, []uint{fixtures[1].ID}},
		{"short platform", ProcessingQuery{EnvID: fixtures[0].EnvironmentID, Platforms: []string{"linux"}}, nil},
		{"long platform", ProcessingQuery{EnvID: fixtures[1].EnvironmentID, Platforms: []string{"linux"}}, []uint{fixtures[1].ID}},
		{"inherited platform", ProcessingQuery{EnvID: fixtures[2].EnvironmentID, Platforms: []string{"linux"}}, nil},
		{"explicit inactive uuid", ProcessingQuery{EnvID: fixtures[0].EnvironmentID, UUIDs: []string{fixtures[0].UUID}}, []uint{fixtures[0].ID}},
		{"explicit inactive host", ProcessingQuery{EnvID: fixtures[0].EnvironmentID, Hosts: []string{fixtures[0].Hostname}}, []uint{fixtures[0].ID}},
		{"no selectors includes inactive", ProcessingQuery{EnvID: fixtures[0].EnvironmentID}, []uint{fixtures[0].ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CreateQueryCarve(tc.data, manager, queries.DistributedQuery{})
			require.NoError(t, err)
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

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
			EnvID: env.ID,
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

func TestBuildQueryTargetRecordsWithoutTargetsUsesEnvironment(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	envs := environments.CreateEnvironment(db)
	env := envs.Empty("dev", "dev.example.com")
	require.NoError(t, envs.Create(&env))

	targets, err := BuildQueryTargetRecords(
		ProcessingQuery{EnvID: env.ID},
		Managers{Envs: envs},
	)
	require.NoError(t, err)
	require.Equal(t, []QueryTargetRecord{{Type: nodes.EnvironmentSelector, Value: env.Name}}, targets)
}

func TestBuildQueryTargetRecordsPreservesExplicitTargets(t *testing.T) {
	targets, err := BuildQueryTargetRecords(
		ProcessingQuery{
			Envs:      []string{"prod"},
			Platforms: []string{"linux"},
			UUIDs:     []string{"UUID-1"},
			Hosts:     []string{"host-1"},
			Tags:      []string{"critical"},
		},
		Managers{},
	)
	require.NoError(t, err)
	require.Equal(t, []QueryTargetRecord{
		{Type: nodes.EnvironmentSelector, Value: "prod"},
		{Type: nodes.PlatformSelector, Value: "linux"},
		{Type: "uuid", Value: "UUID-1"},
		{Type: "host", Value: "host-1"},
		{Type: "tag", Value: "critical"},
	}, targets)
}
