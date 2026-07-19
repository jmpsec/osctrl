package main

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/stretchr/testify/require"
)

func TestPostureProfileScheduleQueriesUsesRequestedPrefix(t *testing.T) {
	schedule, err := postureProfileScheduleQueries("linux-server", "custom:posture:", 0)
	require.NoError(t, err)

	require.Contains(t, schedule, "custom:posture:packages_deb")
	require.NotContains(t, schedule, posture.DefaultQueryPrefix+"packages_deb")
	require.Equal(t, "linux", schedule["custom:posture:packages_deb"].Platform)
	require.True(t, schedule["custom:posture:packages_deb"].Snapshot)
}

func TestPostureProfileScheduleQueriesUsesIntervalOverride(t *testing.T) {
	schedule, err := postureProfileScheduleQueries("linux-server", posture.DefaultQueryPrefix, 3600)
	require.NoError(t, err)

	require.Equal(t, "3600", schedule[posture.DefaultQueryPrefix+"packages_deb"].Interval.String())
	require.Equal(t, "3600", schedule[posture.DefaultQueryPrefix+"users"].Interval.String())
}

func TestPostureProfileScheduleQueriesRejectsUnknownProfile(t *testing.T) {
	_, err := postureProfileScheduleQueries("missing", posture.DefaultQueryPrefix, 0)
	require.Error(t, err)
}
