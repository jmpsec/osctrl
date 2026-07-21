package console_test

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/console"
	"github.com/stretchr/testify/require"
)

func TestDefaultCWD(t *testing.T) {
	require.Equal(t, `C:\`, console.DefaultCWD("windows"))
	require.Equal(t, "/", console.DefaultCWD("darwin"))
	require.Equal(t, "/", console.DefaultCWD("linux"))
	require.Equal(t, "/", console.DefaultCWD(""))
}

func TestParseLocalCommands(t *testing.T) {
	for _, input := range []string{"pwd", "help", "clear"} {
		got, err := console.Parse(input, "/etc", "linux")
		require.NoError(t, err)
		require.Equal(t, console.CommandLocal, got.Kind)
		require.Equal(t, input, got.Command)
	}
}

func TestParseLSResolvesPOSIXPath(t *testing.T) {
	got, err := console.Parse("ls ssh", "/etc", "linux")
	require.NoError(t, err)
	require.Equal(t, console.CommandRemote, got.Kind)
	require.Equal(t, "ls", got.Command)
	require.Equal(t, "/etc/ssh", got.Path)
	require.Contains(t, got.SQL, "from file")
	require.Contains(t, got.SQL, "directory = '/etc/ssh'")
}

func TestParseStatResolvesWindowsPath(t *testing.T) {
	got, err := console.Parse(`stat Windows\System32`, `C:\`, "windows")
	require.NoError(t, err)
	require.Equal(t, `C:\Windows\System32`, got.Path)
	require.Contains(t, got.SQL, "from file")
	require.Contains(t, got.SQL, `path = 'C:\Windows\System32'`)
}

func TestParseRawSQLRequiresSelect(t *testing.T) {
	got, err := console.Parse("sql select * from osquery_info", "/", "linux")
	require.NoError(t, err)
	require.Equal(t, "sql", got.Command)
	require.Equal(t, "select * from osquery_info", got.SQL)

	_, err = console.Parse("sql delete from processes", "/", "linux")
	require.Error(t, err)
	require.Contains(t, err.Error(), "SELECT")

	_, err = console.Parse("sql select 1; select 2", "/", "linux")
	require.Error(t, err)
	require.Contains(t, err.Error(), "single")
}

func TestParseRejectsShellSyntax(t *testing.T) {
	for _, input := range []string{"ls /tmp | head", "ls > out", "ls && ps", "cat /etc/passwd"} {
		_, err := console.Parse(input, "/", "linux")
		require.Error(t, err, input)
	}
}
