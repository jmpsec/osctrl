package main

import (
	"strconv"
	"testing"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/stretchr/testify/require"
)

func storedSensitivePaths(t *testing.T, r *parityRig, envID uint) []environments.SensitivePath {
	t.Helper()
	rows, err := r.Envs.SensitivePaths(envID)
	require.NoError(t, err)
	return rows
}

func TestSensitivePathsBothModes(t *testing.T) {
	r := newParityRig(t)
	env, err := r.Envs.Get("dev")
	require.NoError(t, err)
	r.SeedEnv("prod")
	other, err := r.Envs.Get("prod")
	require.NoError(t, err)
	for mode, run := range r.modes() {
		_, err := run("environment", "sensitive-paths", "add", "-e", env.UUID, "--path", "/ETC//shadow")
		require.NoError(t, err, mode)
		rows := storedSensitivePaths(t, r, env.ID)
		require.Len(t, rows, 1, mode)
		require.Equal(t, "/etc/shadow", rows[0].Path, mode)
		out, err := run("-o", "json", "environment", "sensitive-paths", "list", "-e", "dev")
		require.NoError(t, err, mode)
		require.Contains(t, out, "/etc/shadow", mode)

		// bad path: error surfaced, nothing stored
		_, err = run("environment", "sensitive-paths", "add", "-e", env.UUID, "--path", "etc/shadow")
		require.ErrorContains(t, err, "path must be absolute", mode)
		require.Len(t, storedSensitivePaths(t, r, env.ID), 1, mode)

		// id of another environment cannot be removed
		o, err := r.Envs.AddSensitivePath(other.ID, "/other/"+mode, "t")
		require.NoError(t, err)
		_, err = run("environment", "sensitive-paths", "remove", "-e", env.UUID, "--id", strconv.Itoa(int(o.ID)))
		require.Error(t, err, mode)
		require.Len(t, storedSensitivePaths(t, r, other.ID), 1, mode)
		require.NoError(t, r.Envs.DeleteSensitivePath(other.ID, o.ID))

		_, err = run("environment", "sensitive-paths", "remove", "-e", env.UUID, "--id", strconv.Itoa(int(rows[0].ID)))
		require.NoError(t, err, mode)
		require.Empty(t, storedSensitivePaths(t, r, env.ID), mode)
	}
}
