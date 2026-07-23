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

func TestParseEntersOsqueryMode(t *testing.T) {
	for _, input := range []string{"sql", "osquery"} {
		got, err := console.Parse(input, "/", "linux")
		require.NoError(t, err)
		require.Equal(t, console.CommandMode, got.Kind)
		require.Equal(t, input, got.Command)
		require.Equal(t, "osquery", got.Mode)
	}
}

func TestParseOsqueryModeTreatsInputAsSQL(t *testing.T) {
	got, err := console.ParseInput("select * from osquery_info", "/", "linux", true)
	require.NoError(t, err)
	require.Equal(t, console.CommandRemote, got.Kind)
	require.Equal(t, "sql", got.Command)
	require.Equal(t, "select * from osquery_info", got.SQL)

	_, err = console.ParseInput("delete from processes", "/", "linux", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SELECT")
}

func TestParseOsqueryModeExit(t *testing.T) {
	for _, input := range []string{"exit", "quit", ".exit"} {
		got, err := console.ParseInput(input, "/", "linux", true)
		require.NoError(t, err)
		require.Equal(t, console.CommandExitMode, got.Kind)
		require.Equal(t, "osquery", got.Mode)
	}
}

func TestParseOsqueryModeTables(t *testing.T) {
	got, err := console.ParseInput(".tables", "/", "linux", true)
	require.NoError(t, err)
	require.Equal(t, console.CommandLocal, got.Kind)
	require.Equal(t, "tables", got.Command)
	require.Equal(t, "osquery", got.Mode)

	_, err = console.Parse(".tables", "/", "linux")
	require.Error(t, err)
}

func TestParseGetCreatesCarveCommand(t *testing.T) {
	got, err := console.Parse("get ssh/sshd_config", "/etc", "linux")
	require.NoError(t, err)
	require.Equal(t, console.CommandCarve, got.Kind)
	require.Equal(t, "get", got.Command)
	require.Equal(t, "/etc/ssh/sshd_config", got.Path)

	_, err = console.Parse("get", "/", "linux")
	require.Error(t, err)
	require.Contains(t, err.Error(), "path")
}

func TestParseRejectsShellSyntax(t *testing.T) {
	for _, input := range []string{"ls /tmp | head", "ls > out", "ls && ps", "cat /etc/passwd"} {
		_, err := console.Parse(input, "/", "linux")
		require.Error(t, err, input)
	}
}
