package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/stretchr/testify/require"
)

func seedSettings(t *testing.T, r *parityRig) *settings.Settings {
	t.Helper()
	sm := settings.NewSettings(r.DB)
	require.NoError(t, sm.NewStringValue("tls", "s-set", "a", settings.NoEnvironmentID))
	require.NoError(t, sm.NewBooleanValue("tls", "b-set", false, settings.NoEnvironmentID))
	require.NoError(t, sm.NewIntegerValue("tls", "i-set", 1, settings.NoEnvironmentID))
	return sm
}

func TestSettingsShowParity(t *testing.T) {
	r := newParityRig(t)
	seedSettings(t, r)
	dbOut, err := r.RunDB("settings", "show")
	require.NoError(t, err)
	apiOut, err := r.RunAPI("settings", "show")
	require.NoError(t, err)
	require.Contains(t, dbOut, "s-set")
	require.Equal(t, dbOut, apiOut)
}

func TestSettingsUpdateAPISendsTypedField(t *testing.T) {
	r := newParityRig(t)
	sm := seedSettings(t, r)
	_, err := r.RunAPI("settings", "update", "-s", "tls", "-n", "s-set", "-t", "string", "--string", "z")
	require.NoError(t, err)
	_, err = r.RunAPI("settings", "update", "-s", "tls", "-n", "b-set", "-t", "boolean", "--true")
	require.NoError(t, err)
	_, err = r.RunAPI("settings", "update", "-s", "tls", "-n", "i-set", "-t", "integer", "--integer", "42")
	require.NoError(t, err)
	v, _ := sm.RetrieveValue("tls", "s-set", settings.NoEnvironmentID)
	require.Equal(t, "z", v.String)
	v, _ = sm.RetrieveValue("tls", "b-set", settings.NoEnvironmentID)
	require.True(t, v.Boolean)
	v, _ = sm.RetrieveValue("tls", "i-set", settings.NoEnvironmentID)
	require.Equal(t, int64(42), v.Integer)
	// type mismatch: API's 400 is shown, value unchanged
	_, err = r.RunAPI("settings", "update", "-s", "tls", "-n", "i-set", "-t", "string", "--string", "x")
	require.ErrorContains(t, err, "400")
	v, _ = sm.RetrieveValue("tls", "i-set", settings.NoEnvironmentID)
	require.Equal(t, int64(42), v.Integer)
}

func TestSettingsUpdateInfoRejectedInAPIMode(t *testing.T) {
	r := newParityRig(t)
	sm := seedSettings(t, r)
	_, err := r.RunAPI("settings", "update", "-s", "tls", "-n", "s-set", "-t", "string", "--string", "z", "--info", "i")
	require.EqualError(t, err, "--info is not supported in API mode")
	v, _ := sm.RetrieveValue("tls", "s-set", settings.NoEnvironmentID)
	require.Equal(t, "a", v.String)
}

func TestSettingsUpdateNonAdminShows403(t *testing.T) {
	r := newParityRig(t)
	sm := seedSettings(t, r)
	tok := r.SeedUser("plain", false)
	_, err := r.RunAPIAs(tok, "settings", "update", "-s", "tls", "-n", "s-set", "-t", "string", "--string", "z")
	require.ErrorContains(t, err, "403")
	v, _ := sm.RetrieveValue("tls", "s-set", settings.NoEnvironmentID)
	require.Equal(t, "a", v.String)
}

func TestSettingsUpdateMissingAPI404(t *testing.T) {
	r := newParityRig(t)
	_, err := r.RunAPI("settings", "update", "-s", "tls", "-n", "nope", "-t", "string", "--string", "z")
	require.ErrorContains(t, err, "404")
}

func TestSettingsUpdateValidationReturnsError(t *testing.T) {
	r := newParityRig(t)
	_, err := r.RunAPI("settings", "update", "-s", "tls", "-t", "string")
	require.ErrorContains(t, err, "name is required")
	_, err = r.RunAPI("settings", "update", "-s", "tls", "-n", "x", "-t", "float")
	require.ErrorContains(t, err, "unknown type")
}

func TestSettingsUpdateValidationParity(t *testing.T) {
	r := newParityRig(t)
	sm := seedSettings(t, r)
	require.NoError(t, sm.NewIntegerValue("api", settings.InactiveHours, 24, settings.NoEnvironmentID))
	require.NoError(t, sm.NewIntegerValue("api", settings.AuditLogRetentionDays, 90, settings.NoEnvironmentID))
	bad := [][]string{
		{"-s", "tls", "-n", "i-set", "-t", "string", "--string", "x"},
		{"-s", "tls", "-n", "s-set", "-t", "integer", "--integer", "3"},
		{"-s", "api", "-n", settings.InactiveHours, "-t", "integer", "--integer", "0"},
		{"-s", "api", "-n", settings.InactiveHours, "-t", "integer", "--integer", "-5"},
		{"-s", "api", "-n", settings.AuditLogRetentionDays, "-t", "integer", "--integer", "0"},
	}
	for _, a := range bad {
		_, errDB := r.RunDB(append([]string{"settings", "update"}, a...)...)
		_, errAPI := r.RunAPI(append([]string{"settings", "update"}, a...)...)
		require.Error(t, errDB, a)
		require.Error(t, errAPI, a)
	}
	for name, want := range map[string]int64{settings.InactiveHours: 24, settings.AuditLogRetentionDays: 90} {
		v, _ := sm.RetrieveValue("api", name, settings.NoEnvironmentID)
		require.Equal(t, want, v.Integer)
	}
	v, _ := sm.RetrieveValue("tls", "i-set", settings.NoEnvironmentID)
	require.Equal(t, settings.TypeInteger, v.Type)
	require.Equal(t, int64(1), v.Integer)
	// valid values pass in DB mode
	_, err := r.RunDB("settings", "update", "-s", "api", "-n", settings.InactiveHours, "-t", "integer", "--integer", "48")
	require.NoError(t, err)
	v, _ = sm.RetrieveValue("api", settings.InactiveHours, settings.NoEnvironmentID)
	require.Equal(t, int64(48), v.Integer)
}
