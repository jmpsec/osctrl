package console

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/jmpsec/osctrl/pkg/filequery"
)

var forbiddenShellSyntax = regexp.MustCompile(`[|&;<>]`)
var forbiddenURLSyntax = regexp.MustCompile(`[|;<>]`)

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
	case "hash":
		return pathTableCommand(cmd, args, cwd, platform, "select path, directory, md5, sha1, sha256 from hash where path = %s")
	case "mime", "magic":
		return pathTableCommand(cmd, args, cwd, platform, "select path, mime_type, mime_encoding, data from magic where path = %s")
	case "curl":
		if args == "" {
			return ParsedCommand{}, fmt.Errorf("curl requires a URL")
		}
		if forbiddenURLSyntax.MatchString(args) || strings.ContainsAny(args, " \t\r\n") {
			return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
		}
		parsedURL, err := url.Parse(args)
		if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
			return ParsedCommand{}, fmt.Errorf("curl requires an http or https URL")
		}
		return ParsedCommand{Kind: CommandRemote, Command: "curl", SQL: fmt.Sprintf("select url, method, response_code, round_trip_time, bytes, result from curl where url = %s", quoteSQL(args))}, nil
	case "ports":
		if args != "" {
			return ParsedCommand{}, fmt.Errorf("ports does not accept arguments")
		}
		return ParsedCommand{Kind: CommandRemote, Command: "ports", SQL: "select lp.pid, p.name, p.path, lp.port, lp.protocol, lp.family, lp.address from listening_ports lp left join processes p on p.pid = lp.pid order by port, protocol"}, nil
	case "sockets":
		if args != "" {
			return ParsedCommand{}, fmt.Errorf("sockets does not accept arguments")
		}
		return ParsedCommand{Kind: CommandRemote, Command: "sockets", SQL: "select pid, family, protocol, local_address, local_port, remote_address, remote_port, state, path from process_open_sockets order by pid, local_port"}, nil
	case "lsof":
		pid, err := parsePIDArg(cmd, args)
		if err != nil {
			return ParsedCommand{}, err
		}
		return ParsedCommand{Kind: CommandRemote, Command: "lsof", SQL: fmt.Sprintf("select pid, fd, path from process_open_files where pid = %d order by fd", pid)}, nil
	case "env":
		pid, err := parsePIDArg(cmd, args)
		if err != nil {
			return ParsedCommand{}, err
		}
		return ParsedCommand{Kind: CommandRemote, Command: "env", SQL: fmt.Sprintf("select pid, key, value from process_envs where pid = %d order by key", pid)}, nil
	case "routes":
		return noArgSQL(cmd, args, "select destination, netmask, gateway, source, flags, interface, mtu, metric, type from routes order by destination, metric")
	case "dns":
		return noArgSQL(cmd, args, "select type, address, netmask, options from dns_resolvers order by type, address")
	case "users":
		return noArgSQL(cmd, args, "select uid, gid, username, description, directory, shell, type, is_hidden from users order by username")
	case "loggedin":
		return noArgSQL(cmd, args, "select type, user, tty, host, time, pid from logged_in_users order by time desc")
	case "sudoers":
		return noArgSQL(cmd, args, "select source, header, rule_details from sudoers order by header, rule_details")
	case "autoruns":
		return noArgSQL(cmd, args, "select path, name, source from autoexec order by name, path")
	case "cron":
		return noArgSQL(cmd, args, "select event, minute, hour, day_of_month, month, day_of_week, command, path from crontab order by path, event")
	case "launchd":
		return noArgSQL(cmd, args, "select label, name, program, path, run_at_load, keep_alive, disabled, username from launchd order by label, path")
	case "services":
		return noArgSQL(cmd, args, "select name, display_name, status, pid, start_type, path, user_account from services order by name")
	case "tasks":
		return noArgSQL(cmd, args, "select name, action, path, enabled, state, hidden, last_run_time, next_run_time from scheduled_tasks order by name")
	case "certs":
		return noArgSQL(cmd, args, "select common_name, issuer, ca, self_signed, not_valid_before, not_valid_after, sha1, path, username from certificates order by common_name, path")
	case "diskenc":
		return noArgSQL(cmd, args, "select name, uuid, encrypted, type, encryption_status, filevault_status from disk_encryption order by name")
	case "os":
		return noArgSQL(cmd, args, "select name, version, major, minor, patch, build, platform, platform_like, arch, install_date from os_version")
	case "sysinfo":
		return noArgSQL(cmd, args, "select hostname, uuid, cpu_brand, cpu_physical_cores, cpu_logical_cores, physical_memory, hardware_vendor, hardware_model, hardware_serial from system_info")
	case "uptime":
		return noArgSQL(cmd, args, "select days, hours, minutes, seconds, total_seconds from uptime")
	case "packages":
		return packagesCommand(args, platform)
	case "extensions":
		return noArgSQL(cmd, args, "select 'chrome' as browser, name, identifier, version, profile, path, state from chrome_extensions union all select 'firefox' as browser, name, identifier, version, location as profile, path, case when active = '1' then 'active' else 'inactive' end as state from firefox_addons order by browser, name")
	case "firewall":
		return firewallCommand(args, platform)
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

func pathTableCommand(cmd, args, cwd, platform, format string) (ParsedCommand, error) {
	if args == "" {
		return ParsedCommand{}, fmt.Errorf("%s requires a path", cmd)
	}
	if forbiddenShellSyntax.MatchString(args) {
		return ParsedCommand{}, fmt.Errorf("shell syntax is not supported")
	}
	target := filequery.ResolvePath(args, cwd, platform)
	return ParsedCommand{Kind: CommandRemote, Command: cmd, Path: target, SQL: fmt.Sprintf(format, quoteSQL(target))}, nil
}

func noArgSQL(cmd, args, sql string) (ParsedCommand, error) {
	if args != "" {
		return ParsedCommand{}, fmt.Errorf("%s does not accept arguments", cmd)
	}
	return ParsedCommand{Kind: CommandRemote, Command: cmd, SQL: sql}, nil
}

func parsePIDArg(cmd, args string) (int, error) {
	if args == "" {
		return 0, fmt.Errorf("%s requires a pid", cmd)
	}
	pid, err := strconv.Atoi(args)
	if err != nil || pid < 0 {
		return 0, fmt.Errorf("%s requires a numeric pid", cmd)
	}
	return pid, nil
}

func packagesCommand(args, platform string) (ParsedCommand, error) {
	if args != "" {
		return ParsedCommand{}, fmt.Errorf("packages does not accept arguments")
	}
	switch strings.ToLower(platform) {
	case "darwin":
		return ParsedCommand{Kind: CommandRemote, Command: "packages", SQL: "select name, version, path, 'homebrew' as source from homebrew_packages order by name"}, nil
	case "windows":
		return ParsedCommand{Kind: CommandRemote, Command: "packages", SQL: "select name, version, install_location as path, publisher as source from programs order by name"}, nil
	default:
		return ParsedCommand{Kind: CommandRemote, Command: "packages", SQL: "select name, version, arch, source, 'deb' as type from deb_packages union all select name, version || '-' || release as version, arch, source, 'rpm' as type from rpm_packages order by name"}, nil
	}
}

func firewallCommand(args, platform string) (ParsedCommand, error) {
	if args != "" {
		return ParsedCommand{}, fmt.Errorf("firewall does not accept arguments")
	}
	switch strings.ToLower(platform) {
	case "windows":
		return ParsedCommand{Kind: CommandRemote, Command: "firewall", SQL: "select name, app_name, action, enabled, direction, protocol, local_ports, remote_ports from windows_firewall_rules order by name"}, nil
	case "darwin":
		return ParsedCommand{Kind: CommandRemote, Command: "firewall", SQL: "select allow_signed_enabled, firewall_unload, global_state, logging_enabled, logging_option, stealth_enabled, version from alf"}, nil
	default:
		return ParsedCommand{Kind: CommandRemote, Command: "firewall", SQL: "select filter_name, chain, policy, target, protocol, src_ip, src_port, dst_ip, dst_port, packets, bytes from iptables order by filter_name, chain"}, nil
	}
}

func quoteSQL(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func helpText() string {
	return `Supported commands:

Navigation:
  pwd              show current directory
  cd <path>        change directory
  ls [path]        list directory contents

Files:
  stat <path>      show file metadata
  hash <path>      hash a file
  mime <path>      identify file type
  get <path>       carve a file from the node

Processes:
  ps               list processes
  lsof <pid>       list open files for a process
  env <pid>        show process environment variables

Network:
  curl <url>       request a URL from the node
  ports            show listening ports
  sockets          show open network sockets
  routes           show routes
  dns              show DNS resolvers

System:
  os               show OS version
  sysinfo          show hardware and host identity
  uptime           show uptime
  users            list local users
  loggedin         list active logins
  sudoers          show sudo rules
  certs            list certificates
  diskenc          show disk encryption status
  firewall         show host firewall rules

Persistence and software:
  autoruns         show automatic execution entries
  cron             show cron entries
  launchd          show macOS launch jobs
  services         show Windows services
  tasks            show Windows scheduled tasks
  packages         list installed packages
  extensions       list browser extensions

Osquery:
  sql [select ...] run read-only osquery SQL, or enter osquery mode
  osquery          enter osquery mode
  .tables          list tables while in osquery mode
  .exit            leave osquery mode

Console:
  help             show this help
  clear            clear the console`
}
