package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestTLSNodeSourceEnvironmentThresholds(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	s := newTLSNodeSource(nodes.CreateNodes(db), settings.NewSettings(db), environments.CreateEnvironment(db))
	require.Equal(t, settings.DefaultInactiveHours, s.threshold(1))
	require.Equal(t, settings.DefaultInactiveHours, (&tlsNodeSource{}).threshold(1))
	require.NoError(t, s.settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, 24, 0))
	for i, name := range []string{"short", "long", "inherited"} {
		e := s.envs.Empty(name, name+".example.com")
		require.NoError(t, s.envs.Create(&e))
		if i < 2 {
			require.NoError(t, s.settings.NewIntegerValue(config.ServiceAPI, settings.InactiveHours, []int64{2, 168}[i], e.ID))
		}
		require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: strings.ToUpper(name), Environment: e.Name, EnvironmentID: e.ID, LastSeen: time.Now().Add(-48 * time.Hour)}).Error)
	}
	active, err := s.ActiveNodes(context.Background())
	require.NoError(t, err)
	require.Len(t, active, 1)
	require.Equal(t, "LONG", active[0].UUID)
	require.True(t, active[0].Active)
	inactive, err := s.InactiveNodes(context.Background())
	require.NoError(t, err)
	require.Len(t, inactive, 2)
	require.ElementsMatch(t, []string{"SHORT", "INHERITED"}, []string{inactive[0].UUID, inactive[1].UUID})
	require.False(t, inactive[0].Active)
	require.False(t, inactive[1].Active)
}
