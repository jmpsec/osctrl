//go:build unix

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// Generated configuration holds secrets: it is never readable by other users,
// whatever the umask, and an overwrite tightens an existing loose file.
func TestGenerateGenericConfigFileIsPrivate(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := filepath.Join(t.TempDir(), "config")
	path := filepath.Join(dir, "api.yml")

	require.NoError(t, GenerateGenericConfigFile(path, map[string]string{"secret": "x"}, false))
	st, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	d, err := os.Stat(dir)
	require.NoError(t, err)
	require.Zero(t, d.Mode().Perm()&0o007, "directory must not be world-accessible")

	require.NoError(t, os.Chmod(path, 0o644))
	require.NoError(t, GenerateGenericConfigFile(path, map[string]string{"secret": "y"}, true))
	st, err = os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}
