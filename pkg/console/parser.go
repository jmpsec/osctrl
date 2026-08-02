package console

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/jmpsec/osctrl/pkg/filequery"
)

var forbiddenShellSyntax = regexp.MustCompile(`[|&;<>]`)

func DefaultCWD(platform string) string {
	return filequery.DefaultRoot(platform)
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
		target := filequery.ResolvePath(args, cwd, platform)
		return ParsedCommand{Kind: CommandCarve, Command: "get", Path: target}, nil
	case "ls":
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := filequery.ResolvePath(args, cwd, platform)
		sql := filequery.ListDirectorySQL(target)
		return ParsedCommand{Kind: CommandRemote, Command: "ls", Path: target, SQL: sql}, nil
	case "stat":
		if args == "" {
			return ParsedCommand{}, fmt.Errorf("stat requires a path")
		}
		if forbiddenShellSyntax.MatchString(args) {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		target := filequery.ResolvePath(args, cwd, platform)
		sql := filequery.StatPathSQL(target)
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
		target := filequery.ResolvePath(args, cwd, platform)
		sql := fmt.Sprintf("select path, type from file where path = '%s' and type = 'directory'", strings.ReplaceAll(target, "'", "''"))
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

func helpText() string {
	return "Supported commands: pwd, cd <path>, ls [path], stat <path>, ps, sql [select ...], osquery, get <path>, help, clear. In osquery mode: .tables, .exit"
}
