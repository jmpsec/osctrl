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
	"github.com/jmpsec/osctrl/pkg/vulns"
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

func TestTLSFindingSourceAddsTheEnvironmentName(t *testing.T) {
	dsn := "file:" + strings.NewReplacer("/", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodes.CreateNodes(db)
	inv, err := vulns.NewInventory(db)
	require.NoError(t, err)
	env := environments.TLSEnvironment{UUID: "env-a", Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	require.NoError(t, db.Create(&nodes.OsqueryNode{UUID: "N1", Hostname: "web-01", EnvironmentID: env.ID}).Error)
	require.NoError(t, db.Create(&vulns.Finding{NodeUUID: "N1", EnvironmentID: env.ID, AdvisoryID: "DSA-1",
		Ecosystem: "Debian:12", Package: "openssl", Severity: "critical", KEV: true, Confidence: vulns.ConfidenceConfirmed}).Error)

	s := newTLSFindingSource(inv, envs)
	got, err := s.FindingsAfter(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "prod", got[0].Environment)
	require.Equal(t, "web-01", got[0].Hostname)
	require.Equal(t, "critical", got[0].Severity)

	latest, err := s.LatestFindingID(context.Background())
	require.NoError(t, err)
	require.Equal(t, got[0].ID, latest)
}

func TestTLSFindingSourceListsEscalations(t *testing.T) {
	dsn := "file:" + strings.NewReplacer("/", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	envs := environments.CreateEnvironment(db)
	nodes.CreateNodes(db)
	inv, err := vulns.NewInventory(db)
	require.NoError(t, err)
	env := environments.TLSEnvironment{UUID: "env-a", Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	f := vulns.Finding{NodeUUID: "N1", EnvironmentID: env.ID, AdvisoryID: "DSA-1", Ecosystem: "Debian:12",
		Package: "openssl", Severity: "high", KEV: true, Confidence: vulns.ConfidenceConfirmed}
	require.NoError(t, db.Create(&f).Error)
	require.NoError(t, db.Create(&vulns.Escalation{FindingID: f.ID, PrevSeverity: "high", CreatedAt: time.Now()}).Error)

	s := newTLSFindingSource(inv, envs)
	got, err := s.EscalationsAfter(context.Background(), 0, 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].Escalated)
	require.Equal(t, "prod", got[0].Environment)
	require.Equal(t, "high", got[0].PrevSeverity)
	require.False(t, got[0].PrevKEV)
	latest, err := s.LatestEscalationID(context.Background())
	require.NoError(t, err)
	require.Equal(t, got[0].ID, latest)
}
