package health

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/stretchr/testify/require"
)

func TestUpgradeInfoBeforeAnyCheck(t *testing.T) {
	c := NewVersionCache("0.5.8")
	info := c.Info("0.5.8")
	require.Equal(t, "0.5.8", info.Current)
	require.Empty(t, info.Latest, "no check has run yet")
	require.False(t, info.Checked)
}

func TestUpgradeInfoAfterCheck(t *testing.T) {
	c := NewVersionCache("0.5.8")
	c.Set(version.VersionData{LatestRelease: "0.5.9", SuggestedRelease: "0.5.8"})
	info := c.Info("0.5.8")
	require.True(t, info.Checked)
	require.Equal(t, "0.5.9", info.Latest)
	require.Equal(t, "0.5.8", info.Suggested)
	require.False(t, info.Skew)
}

func TestUpgradeInfoReportsServiceSkew(t *testing.T) {
	c := NewVersionCache("0.5.8")
	c.Set(version.VersionData{LatestRelease: "0.5.9", SuggestedRelease: "0.5.8"})
	info := c.Info("0.5.7")
	require.True(t, info.Skew)
	require.Equal(t, "0.5.7", info.TLS)
	require.Equal(t, "0.5.8", info.API)
}
