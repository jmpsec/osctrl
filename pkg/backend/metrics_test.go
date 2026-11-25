package backend

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestRegisterDBPoolMetrics(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory"), &gorm.Config{})
	require.NoError(t, err)
	manager := &DBManager{Conn: db}

	reg := prometheus.NewRegistry()
	RegisterDBPoolMetrics(reg, manager)

	families, err := reg.Gather()
	require.NoError(t, err)
	found := false
	for _, family := range families {
		if family.GetName() == "osctrl_db_pool_open_connections" {
			found = true
			require.Len(t, family.GetMetric(), 1)
			require.Equal(t, "primary", family.GetMetric()[0].GetLabel()[0].GetValue())
		}
	}
	require.True(t, found, "primary pool metric missing")
}
