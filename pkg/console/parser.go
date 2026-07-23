package console

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var forbiddenShellSyntax = regexp.MustCompile(`[|&;<>]`)

func DefaultCWD(platform string) string {
	if strings.EqualFold(platform, "windows") {
		return `C:\`
	}
	return "/"
}

func Parse(input, cwd, platform string) (ParsedCommand, error) {
	return ParseInput(input, cwd, platform, false)
}

func ParseInput(input, cwd, platform string, osqueryMode bool) (ParsedCommand, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParsedCommand{}, fmt.Errorf("command can not be empty")
	}

	if osqueryMode {
		switch strings.ToLower(input) {
		case "exit", "quit", ".exit":
			return ParsedCommand{Kind: CommandExitMode, Command: strings.ToLower(input), Mode: "osquery", Message: "leaving osquery mode"}, nil
		case ".tables":
			return ParsedCommand{Kind: CommandLocal, Command: "tables", Mode: "osquery"}, nil
		}
		if err := validateSelect(input); err != nil {
			return ParsedCommand{}, err
		}
		return ParsedCommand{Kind: CommandRemote, Command: "sql", Mode: "osquery", SQL: input}, nil
	}

	fields := strings.Fields(input)
	cmd := strings.ToLower(fields[0])
	args := strings.TrimSpace(strings.TrimPrefix(input, fields[0]))

	switch cmd {
	case "pwd":
		return ParsedCommand{Kind: CommandLocal, Command: "pwd", Output: cwd}, nil
	case "help":
		return ParsedCommand{Kind: CommandLocal, Command: "help", Output: helpText()}, nil
	case "clear":
		return ParsedCommand{Kind: CommandLocal, Command: "clear"}, nil
	case "get":
		if args == "" {
			return ParsedCommand{}, fmt.Errorf("get requires a path")
		}
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := resolvePath(args, cwd, platform)
		return ParsedCommand{Kind: CommandCarve, Command: "get", Path: target}, nil
	case "ls":
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := resolvePath(args, cwd, platform)
		sql := fmt.Sprintf("select path, filename, directory, type, size, mode, uid, gid, mtime from file where directory = %s", quoteSQL(target))
		return ParsedCommand{Kind: CommandRemote, Command: "ls", Path: target, SQL: sql}, nil
	case "stat":
		if args == "" {
			return ParsedCommand{}, fmt.Errorf("stat requires a path")
		}
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := resolvePath(args, cwd, platform)
		sql := fmt.Sprintf("select path, filename, directory, type, size, mode, uid, gid, mtime, atime, ctime from file where path = %s", quoteSQL(target))
		return ParsedCommand{Kind: CommandRemote, Command: "stat", Path: target, SQL: sql}, nil
	case "ps":
		if args != "" {
			return ParsedCommand{}, fmt.Errorf("ps does not accept arguments")
		}
		return ParsedCommand{Kind: CommandRemote, Command: "ps", SQL: "select pid, parent, name, path, cmdline, state, uid, gid, start_time from processes order by pid"}, nil
	case "cd":
		if args == "" {
			return ParsedCommand{}, fmt.Errorf("cd requires a path")
		}
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := resolvePath(args, cwd, platform)
		sql := fmt.Sprintf("select path, type from file where path = %s and type = 'directory'", quoteSQL(target))
		return ParsedCommand{Kind: CommandRemote, Command: "cd", Path: target, SQL: sql}, nil
	case "sql":
		sql := strings.TrimSpace(args)
		if sql == "" {
			return ParsedCommand{Kind: CommandMode, Command: "sql", Mode: "osquery", Message: "entering osquery mode"}, nil
		}
		if err := validateSelect(sql); err != nil {
			return ParsedCommand{}, err
		}
		return ParsedCommand{Kind: CommandRemote, Command: "sql", SQL: sql}, nil
	case "osquery":
		if args != "" {
			return ParsedCommand{}, fmt.Errorf("osquery does not accept arguments")
		}
		return ParsedCommand{Kind: CommandMode, Command: "osquery", Mode: "osquery", Message: "entering osquery mode"}, nil
	default:
		return ParsedCommand{}, fmt.Errorf("unsupported command %q", cmd)
	}
}

func validateSelect(sql string) error {
	lower := strings.ToLower(strings.TrimSpace(sql))
	if !strings.HasPrefix(lower, "select ") {
		return fmt.Errorf("raw SQL must be a SELECT statement")
	}
	if strings.Count(sql, ";") > 0 {
		return fmt.Errorf("raw SQL must be a single statement without semicolons")
	}
	for _, verb := range []string{" insert ", " update ", " delete ", " drop ", " alter ", " attach ", " detach ", " pragma "} {
		if strings.Contains(" "+lower+" ", verb) {
			return fmt.Errorf("raw SQL must be read-only SELECT")
		}
	}
	return nil
}

func resolvePath(arg, cwd, platform string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		arg = cwd
	}
	if strings.EqualFold(platform, "windows") {
		return resolveWindowsPath(arg, cwd)
	}
	if strings.HasPrefix(arg, "/") {
		return path.Clean(arg)
	}
	return path.Clean(path.Join(cwd, arg))
}

func resolveWindowsPath(arg, cwd string) string {
	arg = strings.ReplaceAll(arg, "/", `\`)
	cwd = strings.ReplaceAll(cwd, "/", `\`)
	if isWindowsAbs(arg) {
		return cleanWindowsPath(arg)
	}
	return cleanWindowsPath(strings.TrimRight(cwd, `\`) + `\` + arg)
}

func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '\\'
}

func cleanWindowsPath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	parts := []string{}
	for _, part := range strings.Split(p, `\`) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(parts) > 1 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return `C:\`
	}
	if len(parts) == 1 && strings.HasSuffix(parts[0], ":") {
		return parts[0] + `\`
	}
	return strings.Join(parts, `\`)
}

func quoteSQL(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func helpText() string {
	return "Supported commands: pwd, cd <path>, ls [path], stat <path>, ps, sql [select ...], osquery, get <path>, help, clear. In osquery mode: .tables, .exit"
}
