package settings

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestAuditRetentionSetting(t *testing.T) {
	db := setupSettingsTestDB(t)
	m := &Settings{DB: db}
	days, err := m.AuditLogRetentionDays()
	require.NoError(t, err)
	require.Equal(t, DefaultAuditLogRetentionDays, days)
	require.Error(t, m.NewIntegerValue(config.ServiceAPI, AuditLogRetentionDays, 0, 0))
	require.NoError(t, m.NewIntegerValue(config.ServiceAPI, AuditLogRetentionDays, 180, 0))
	days, err = m.AuditLogRetentionDays()
	require.NoError(t, err)
	require.EqualValues(t, 180, days)
	require.Error(t, m.SetInteger(-1, config.ServiceAPI, AuditLogRetentionDays, 0))
	// A malformed direct database edit must stop pruning, never shorten retention.
	require.NoError(t, db.Model(&SettingValue{}).Where("name = ?", AuditLogRetentionDays).Update("integer", 0).Error)
	_, err = m.AuditLogRetentionDays()
	require.Error(t, err)
	require.NoError(t, db.Migrator().DropTable(&SettingValue{}))
	_, err = m.AuditLogRetentionDays()
	require.Error(t, err)
}
