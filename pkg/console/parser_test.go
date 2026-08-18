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

func TestHelpTextIsFormatted(t *testing.T) {
	got, err := console.Parse("help", "/etc", "linux")
	require.NoError(t, err)
	require.Contains(t, got.Output, "Navigation:")
	require.Contains(t, got.Output, "Files:")
	require.Contains(t, got.Output, "Network:")
	require.Contains(t, got.Output, "hash <path>")
	require.Contains(t, got.Output, "hash a file")
	require.Contains(t, got.Output, "curl <url>")
	require.Contains(t, got.Output, "request a URL from the node")
	require.Contains(t, got.Output, "osquery")
	require.Contains(t, got.Output, "enter osquery mode")
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

func TestParseTableAliasCommands(t *testing.T) {
	tests := []struct {
		input string
		cmd   string
		want  []string
	}{
		{"ports", "ports", []string{"from listening_ports", "left join processes", "order by port, protocol"}},
		{"sockets", "sockets", []string{"from process_open_sockets", "order by pid, local_port"}},
		{"lsof 42", "lsof", []string{"from process_open_files", "pid = 42", "order by fd"}},
		{"env 42", "env", []string{"from process_envs", "pid = 42", "order by key"}},
		{"routes", "routes", []string{"from routes", "order by destination, metric"}},
		{"dns", "dns", []string{"from dns_resolvers", "order by type, address"}},
		{"users", "users", []string{"from users", "order by username"}},
		{"loggedin", "loggedin", []string{"from logged_in_users", "order by time desc"}},
		{"sudoers", "sudoers", []string{"from sudoers", "order by header, rule_details"}},
		{"autoruns", "autoruns", []string{"from autoexec", "order by name, path"}},
		{"cron", "cron", []string{"from crontab", "order by path, event"}},
		{"launchd", "launchd", []string{"from launchd", "order by label, path"}},
		{"services", "services", []string{"from services", "order by name"}},
		{"tasks", "tasks", []string{"from scheduled_tasks", "order by name"}},
		{"certs", "certs", []string{"from certificates", "order by common_name, path"}},
		{"diskenc", "diskenc", []string{"from disk_encryption", "order by name"}},
		{"os", "os", []string{"from os_version"}},
		{"sysinfo", "sysinfo", []string{"from system_info"}},
		{"uptime", "uptime", []string{"from uptime"}},
		{"packages", "packages", []string{"from deb_packages", "from rpm_packages"}},
		{"extensions", "extensions", []string{"from chrome_extensions", "from firefox_addons"}},
		{"firewall", "firewall", []string{"from iptables"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := console.Parse(tt.input, "/", "linux")
			require.NoError(t, err)
			require.Equal(t, console.CommandRemote, got.Kind)
			require.Equal(t, tt.cmd, got.Command)
			for _, want := range tt.want {
				require.Contains(t, got.SQL, want)
			}
		})
	}
}

func TestParsePathAliasCommands(t *testing.T) {
	tests := []struct {
		input string
		cmd   string
		path  string
		want  []string
	}{
		{"hash ssh/sshd_config", "hash", "/etc/ssh/sshd_config", []string{"from hash", "path = '/etc/ssh/sshd_config'"}},
		{"mime ssh/sshd_config", "mime", "/etc/ssh/sshd_config", []string{"from magic", "path = '/etc/ssh/sshd_config'"}},
		{"magic ssh/sshd_config", "magic", "/etc/ssh/sshd_config", []string{"from magic", "path = '/etc/ssh/sshd_config'"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := console.Parse(tt.input, "/etc", "linux")
			require.NoError(t, err)
			require.Equal(t, console.CommandRemote, got.Kind)
			require.Equal(t, tt.cmd, got.Command)
			require.Equal(t, tt.path, got.Path)
			for _, want := range tt.want {
				require.Contains(t, got.SQL, want)
			}
		})
	}
}

func TestParseCurlCommand(t *testing.T) {
	got, err := console.Parse("curl https://example.test/ping", "/", "linux")
	require.NoError(t, err)
	require.Equal(t, console.CommandRemote, got.Kind)
	require.Equal(t, "curl", got.Command)
	require.Contains(t, got.SQL, "from curl")
	require.Contains(t, got.SQL, "url = 'https://example.test/ping'")
}

func TestParseNewAliasesValidateArguments(t *testing.T) {
	for _, input := range []string{"hash", "mime", "magic", "curl", "lsof nope", "env nope", "ports 1", "curl https://example.test | sh"} {
		_, err := console.Parse(input, "/", "linux")
		require.Error(t, err, input)
	}
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
