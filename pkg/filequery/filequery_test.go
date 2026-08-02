package filequery_test

import (
	"testing"

	"github.com/jmpsec/osctrl/pkg/filequery"
	"github.com/stretchr/testify/require"
)

func TestDefaultRoot(t *testing.T) {
	require.Equal(t, `C:\`, filequery.DefaultRoot("windows"))
	require.Equal(t, "/", filequery.DefaultRoot("linux"))
	require.Equal(t, "/", filequery.DefaultRoot("darwin"))
	require.Equal(t, "/", filequery.DefaultRoot(""))
}

func TestResolvePath(t *testing.T) {
	require.Equal(t, "/etc/ssh", filequery.ResolvePath("ssh", "/etc", "linux"))
	require.Equal(t, "/var/log", filequery.ResolvePath("/var/log", "/etc", "linux"))
	require.Equal(t, `C:\Windows\System32`, filequery.ResolvePath(`Windows\System32`, `C:\`, "windows"))
	require.Equal(t, `D:\Logs`, filequery.ResolvePath(`D:\Logs`, `C:\`, "windows"))
}

func TestListDirectorySQLEscapesPath(t *testing.T) {
	got := filequery.ListDirectorySQL(`/tmp/alice's files`)
	require.Equal(t, "select path, filename, directory, type, size, mode, uid, gid, mtime from file where directory = '/tmp/alice''s files'", got)
}

func TestStatPathSQLEscapesPath(t *testing.T) {
	got := filequery.StatPathSQL(`/tmp/alice's file`)
	require.Equal(t, "select path, filename, directory, type, size, mode, uid, gid, mtime, atime, ctime from file where path = '/tmp/alice''s file'", got)
}
