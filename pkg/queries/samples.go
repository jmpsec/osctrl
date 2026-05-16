package queries

// Starter osquery query samples shipped with osctrl. Used by:
//   - GET /api/v1/queries/samples — SPA queries/new form populates its
//     QuickTemplates row from this list so new operators have ready-made
//     examples to learn from.
//   - cmd/cli env add — seeds a SavedQuery row per sample into the new
//     environment so the Saves page is not empty out of the box.
//
// Each sample is a pure data record; no database interaction. The list lives
// here (rather than baked into the SPA bundle) so the CLI and the SPA stay
// in sync — both load from the same source.
//
// Editing rules:
//   - Names must be unique. The CLI uses Name as the primary key when
//     seeding into saved_queries (one-row-per-sample-per-env).
//   - SQL must be a single statement and must NOT end in a semicolon —
//     the existing query infrastructure appends one and double-semicolons
//     break some platforms.
//   - Keep platform tags accurate. The SPA filters the templates row by
//     selected platforms in the run form; a sample tagged `linux` won't
//     appear when an operator has only `windows` selected.

// QuerySampleCategory is the closed set of category tags. Surfaced in the
// SPA so templates can group; kept as a typed string so a typo at sample-add
// time becomes a compile error.
type QuerySampleCategory string

const (
	CategoryRecon         QuerySampleCategory = "recon"
	CategoryProcesses     QuerySampleCategory = "processes"
	CategoryUsers         QuerySampleCategory = "users"
	CategoryNetwork       QuerySampleCategory = "network"
	CategoryPersistence   QuerySampleCategory = "persistence"
	CategoryFileIntegrity QuerySampleCategory = "file_integrity"
	CategoryPackages      QuerySampleCategory = "packages"
)

// QuerySamplePlatform — a platform tag a sample claims to support. Aligns
// with pkg/nodes platform buckets (linux / darwin / windows). A sample
// applicable to every platform tagged with `linux, darwin, windows`.
type QuerySamplePlatform string

const (
	PlatformLinux   QuerySamplePlatform = "linux"
	PlatformDarwin  QuerySamplePlatform = "darwin"
	PlatformWindows QuerySamplePlatform = "windows"
)

// QuerySample is one starter sample row.
type QuerySample struct {
	Name        string                `json:"name"`
	Description string                `json:"description"`
	SQL         string                `json:"sql"`
	Category    QuerySampleCategory   `json:"category"`
	Platforms   []QuerySamplePlatform `json:"platforms"`
}

// QuerySamples is the canonical starter library. ~20 entries spanning the
// categories above. Operators are expected to read, clone, and adapt these —
// they are intentionally simple and SELECT-only.
//
// Ordering matters: this is the order the SPA template row renders, so the
// most-commonly-useful samples sit first.
var QuerySamples = []QuerySample{
	// ── recon — quick host snapshots ───────────────────────────────────────
	{
		Name:        "host_overview",
		Description: "Hostname, platform, OS version, kernel — basic host identity.",
		SQL:         "SELECT hostname, computer_name, cpu_brand, physical_memory FROM system_info",
		Category:    CategoryRecon,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "os_version",
		Description: "Operating system name, version, codename, and build identifiers.",
		SQL:         "SELECT name, version, codename, major, minor, patch, platform, platform_like FROM os_version",
		Category:    CategoryRecon,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "kernel_info",
		Description: "Running kernel name and version.",
		SQL:         "SELECT name, version FROM kernel_info",
		Category:    CategoryRecon,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin},
	},
	{
		Name:        "uptime",
		Description: "How long the host has been up — in days, hours, minutes.",
		SQL:         "SELECT days, hours, minutes, seconds FROM uptime",
		Category:    CategoryRecon,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},

	// ── processes ──────────────────────────────────────────────────────────
	{
		Name:        "running_processes",
		Description: "All running processes — pid, name, full path, parent pid.",
		SQL:         "SELECT pid, name, path, parent FROM processes",
		Category:    CategoryProcesses,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "processes_root",
		Description: "Processes running as root / SYSTEM. Quick way to spot abnormal privileged execution.",
		SQL:         "SELECT pid, name, path, uid, cmdline FROM processes WHERE uid = 0",
		Category:    CategoryProcesses,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin},
	},
	{
		Name:        "processes_no_disk",
		Description: "Running processes whose executable on disk is missing — classic injected/memory-only indicator.",
		SQL:         "SELECT pid, name, path FROM processes WHERE on_disk = 0",
		Category:    CategoryProcesses,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},

	// ── users ──────────────────────────────────────────────────────────────
	{
		Name:        "local_users",
		Description: "All local user accounts — username, uid, gid, home directory, shell.",
		SQL:         "SELECT username, uid, gid, directory, shell FROM users",
		Category:    CategoryUsers,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "logged_in_users",
		Description: "Currently logged-in users with login time and remote host.",
		SQL:         "SELECT user, host, time, tty, type FROM logged_in_users",
		Category:    CategoryUsers,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "sudoers_groups",
		Description: "Group memberships — useful for spotting unexpected sudo / wheel / admin members.",
		SQL:         "SELECT username, groupname FROM users JOIN user_groups USING(uid) JOIN groups USING(gid)",
		Category:    CategoryUsers,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin},
	},

	// ── network ────────────────────────────────────────────────────────────
	{
		Name:        "listening_ports",
		Description: "TCP/UDP listeners with the binding process and PID.",
		SQL:         "SELECT pid, port, protocol, address, p.name AS process FROM listening_ports l JOIN processes p USING(pid)",
		Category:    CategoryNetwork,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "active_connections",
		Description: "Established outbound TCP connections — remote IP and port.",
		SQL:         "SELECT pid, local_address, local_port, remote_address, remote_port FROM process_open_sockets WHERE state = 'ESTABLISHED'",
		Category:    CategoryNetwork,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "arp_cache",
		Description: "ARP cache entries — recently-seen MAC↔IP pairs on the LAN.",
		SQL:         "SELECT address, mac, interface FROM arp_cache",
		Category:    CategoryNetwork,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "interface_addresses",
		Description: "All network-interface addresses with subnet masks and broadcast addresses.",
		SQL:         "SELECT interface, address, mask, broadcast FROM interface_addresses",
		Category:    CategoryNetwork,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},

	// ── persistence ────────────────────────────────────────────────────────
	{
		Name:        "crontab_all",
		Description: "Every cron job on the host across system and per-user crontabs.",
		SQL:         "SELECT command, path, minute, hour, day_of_month, month, day_of_week FROM crontab",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin},
	},
	{
		Name:        "systemd_units",
		Description: "Loaded systemd units — name, state, file path. Look for unfamiliar service files.",
		SQL:         "SELECT id, fragment_path, active_state, sub_state, unit_file_state FROM systemd_units",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformLinux},
	},
	{
		Name:        "launchd_overview",
		Description: "macOS launchd jobs — daemons and agents loaded at boot/login.",
		SQL:         "SELECT name, path, program, run_at_load, keep_alive, disabled FROM launchd",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformDarwin},
	},
	{
		Name:        "startup_items",
		Description: "Windows autostart entries — Run/RunOnce registry keys and Startup folders.",
		SQL:         "SELECT name, path, source, status, type FROM startup_items",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformWindows},
	},
	{
		Name:        "scheduled_tasks_windows",
		Description: "Windows Task Scheduler jobs — name, action, last_run_time, enabled state.",
		SQL:         "SELECT name, action, path, enabled, last_run_time, next_run_time FROM scheduled_tasks",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformWindows},
	},
	{
		Name:        "services_windows",
		Description: "Windows services — name, display_name, start_type, status, path on disk.",
		SQL:         "SELECT name, display_name, status, start_type, path FROM services",
		Category:    CategoryPersistence,
		Platforms:   []QuerySamplePlatform{PlatformWindows},
	},

	// ── file integrity ─────────────────────────────────────────────────────
	{
		Name:        "etc_passwd",
		Description: "Hash, size, owner, permissions of /etc/passwd — classic file-integrity check.",
		SQL:         "SELECT path, size, mode, uid, gid, mtime, sha256 FROM file WHERE path = '/etc/passwd'",
		Category:    CategoryFileIntegrity,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin},
	},
	{
		Name:        "etc_hosts_contents",
		Description: "Lines of /etc/hosts — quick way to spot tampering or DNS-override mischief.",
		SQL:         "SELECT address, hostnames FROM etc_hosts",
		Category:    CategoryFileIntegrity,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},
	{
		Name:        "windows_hosts_file",
		Description: "Hash and metadata of the Windows hosts file — should rarely change in a managed fleet.",
		SQL:         "SELECT path, size, mtime, sha256 FROM file WHERE path = 'C:\\Windows\\System32\\drivers\\etc\\hosts'",
		Category:    CategoryFileIntegrity,
		Platforms:   []QuerySamplePlatform{PlatformWindows},
	},
	{
		Name:        "certificates_trusted",
		Description: "Trusted certificates in the system store — recent additions can indicate MITM CA installs.",
		SQL:         "SELECT common_name, subject, issuer, not_valid_after, sha1 FROM certificates",
		Category:    CategoryFileIntegrity,
		Platforms:   []QuerySamplePlatform{PlatformLinux, PlatformDarwin, PlatformWindows},
	},

	// ── packages / installed software ──────────────────────────────────────
	{
		Name:        "installed_packages_deb",
		Description: "Debian / Ubuntu installed packages with version.",
		SQL:         "SELECT name, version, arch FROM deb_packages",
		Category:    CategoryPackages,
		Platforms:   []QuerySamplePlatform{PlatformLinux},
	},
	{
		Name:        "installed_packages_rpm",
		Description: "RHEL / Fedora / CentOS installed RPM packages with version.",
		SQL:         "SELECT name, version, arch FROM rpm_packages",
		Category:    CategoryPackages,
		Platforms:   []QuerySamplePlatform{PlatformLinux},
	},
	{
		Name:        "installed_apps_macos",
		Description: "macOS .app bundles in /Applications — name, version, bundle id.",
		SQL:         "SELECT name, bundle_identifier, bundle_short_version FROM apps",
		Category:    CategoryPackages,
		Platforms:   []QuerySamplePlatform{PlatformDarwin},
	},
	{
		Name:        "installed_programs_windows",
		Description: "Windows installed programs — name, version, publisher, install_date.",
		SQL:         "SELECT name, version, publisher, install_date FROM programs",
		Category:    CategoryPackages,
		Platforms:   []QuerySamplePlatform{PlatformWindows},
	},
}
