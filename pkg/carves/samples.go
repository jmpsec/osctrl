package carves

// Starter file-carve target samples shipped with osctrl. Used by:
//   - GET /api/v1/carves/samples — SPA carves/new form populates its
//     path-templates row from this list so new operators have ready-made
//     forensic targets to start from.
//
// Unlike query samples, carves are not seeded into a persistent library.
// A carve is an incident-response action against a specific path on
// specific nodes; operators run them ad-hoc, not on a schedule. The
// samples below are the "what would I grab first?" common targets.
//
// Coverage spans linux, darwin, windows so every platform has at least
// 6 starting templates regardless of which OS the operator's looking at.

// CarveSampleCategory groups paths so the SPA can label them for the
// operator (Auth / Logs / Registry / etc). Closed set; new categories
// require updating the SPA's label map too.
type CarveSampleCategory string

const (
	CarveCategoryAuth     CarveSampleCategory = "auth"
	CarveCategoryLogs     CarveSampleCategory = "logs"
	CarveCategoryRegistry CarveSampleCategory = "registry"
	CarveCategoryKeychain CarveSampleCategory = "keychain"
	CarveCategoryHistory  CarveSampleCategory = "history"
	CarveCategoryConfig   CarveSampleCategory = "config"
)

// CarveSamplePlatform — aligns with the platform buckets used elsewhere in
// osctrl. Each sample is single-platform because file paths are
// platform-specific by definition.
type CarveSamplePlatform string

const (
	CarvePlatformLinux   CarveSamplePlatform = "linux"
	CarvePlatformDarwin  CarveSamplePlatform = "darwin"
	CarvePlatformWindows CarveSamplePlatform = "windows"
)

// CarveSample is one starter target row.
type CarveSample struct {
	Label    string              `json:"label"`
	Path     string              `json:"path"`
	Platform CarveSamplePlatform `json:"platform"`
	Category CarveSampleCategory `json:"category"`
	// Notes is a brief operator-facing description of why this file is
	// worth grabbing during an investigation. Surfaced as a tooltip in
	// the SPA template row.
	Notes string `json:"notes"`
}

// CarveSamples is the canonical starter library. ~24 entries across the
// three major platforms. Ordering is by platform then category so the SPA's
// template row reads in a predictable shape.
var CarveSamples = []CarveSample{
	// ── Linux — auth ───────────────────────────────────────────────────────
	{
		Label:    "/etc/passwd",
		Path:     "/etc/passwd",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryAuth,
		Notes:    "Local user account database (read by every getpwnam call).",
	},
	{
		Label:    "/etc/shadow",
		Path:     "/etc/shadow",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryAuth,
		Notes:    "Hashed password store — root-readable only; presence in carve output confirms agent ran as root.",
	},
	{
		Label:    "/etc/sudoers",
		Path:     "/etc/sudoers",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryAuth,
		Notes:    "Sudo privilege configuration. Compare across hosts to spot drift.",
	},
	// ── Linux — logs ───────────────────────────────────────────────────────
	{
		Label:    "/var/log/auth.log",
		Path:     "/var/log/auth.log",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryLogs,
		Notes:    "SSH / sudo / PAM authentication events (Debian / Ubuntu).",
	},
	{
		Label:    "/var/log/secure",
		Path:     "/var/log/secure",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryLogs,
		Notes:    "SSH / sudo / PAM authentication events (RHEL / CentOS / Fedora).",
	},
	{
		Label:    "/var/log/syslog",
		Path:     "/var/log/syslog",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryLogs,
		Notes:    "General system messages; correlate with auth.log for a fuller timeline.",
	},
	// ── Linux — history / config ───────────────────────────────────────────
	{
		Label:    "/root/.bash_history",
		Path:     "/root/.bash_history",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryHistory,
		Notes:    "Root shell command history — first thing to grab on suspected compromise.",
	},
	{
		Label:    "/etc/crontab",
		Path:     "/etc/crontab",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryConfig,
		Notes:    "System-wide cron schedule. Check for unfamiliar entries.",
	},
	{
		Label:    "/etc/hosts",
		Path:     "/etc/hosts",
		Platform: CarvePlatformLinux,
		Category: CarveCategoryConfig,
		Notes:    "Local hostname overrides. Tampered entries can redirect traffic.",
	},

	// ── macOS — auth ───────────────────────────────────────────────────────
	{
		Label:    "/etc/passwd",
		Path:     "/etc/passwd",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryAuth,
		Notes:    "Local user account database (legacy; macOS primarily uses OpenDirectory).",
	},
	{
		Label:    "/var/db/dslocal/nodes/Default/users",
		Path:     "/var/db/dslocal/nodes/Default/users",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryAuth,
		Notes:    "Local user records in OpenDirectory (plist files; carve the directory).",
	},
	// ── macOS — keychain / logs ────────────────────────────────────────────
	{
		Label:    "~/Library/Keychains",
		Path:     "/Users",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryKeychain,
		Notes:    "User keychain directories. Carve a specific user's path: /Users/<user>/Library/Keychains.",
	},
	{
		Label:    "/var/log/system.log",
		Path:     "/var/log/system.log",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryLogs,
		Notes:    "Pre-unified-logging system messages.",
	},
	{
		Label:    "/var/log/install.log",
		Path:     "/var/log/install.log",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryLogs,
		Notes:    "Software install / update events — useful for spotting unexpected pkg installs.",
	},
	// ── macOS — history / config ───────────────────────────────────────────
	{
		Label:    "~/.zsh_history (root)",
		Path:     "/var/root/.zsh_history",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryHistory,
		Notes:    "Root zsh history. Adjust path for non-root users: /Users/<user>/.zsh_history.",
	},
	{
		Label:    "/etc/hosts",
		Path:     "/etc/hosts",
		Platform: CarvePlatformDarwin,
		Category: CarveCategoryConfig,
		Notes:    "Local hostname overrides.",
	},

	// ── Windows — auth (registry hives) ────────────────────────────────────
	{
		Label:    `SAM hive`,
		Path:     `C:\Windows\System32\config\SAM`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryRegistry,
		Notes:    "Local account database hive. File is locked while Windows runs; carve from VSS shadow or live-running osquery as SYSTEM.",
	},
	{
		Label:    `SYSTEM hive`,
		Path:     `C:\Windows\System32\config\SYSTEM`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryRegistry,
		Notes:    "System configuration hive. Contains services, drivers, BootKey for SAM decryption.",
	},
	{
		Label:    `SECURITY hive`,
		Path:     `C:\Windows\System32\config\SECURITY`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryRegistry,
		Notes:    "Local security policy hive. Contains LSA secrets and cached domain credentials.",
	},
	// ── Windows — logs ─────────────────────────────────────────────────────
	{
		Label:    `Security event log`,
		Path:     `C:\Windows\System32\winevt\Logs\Security.evtx`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryLogs,
		Notes:    "Windows security audit log — logon events, privilege use, object access.",
	},
	{
		Label:    `System event log`,
		Path:     `C:\Windows\System32\winevt\Logs\System.evtx`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryLogs,
		Notes:    "System events — services, drivers, hardware. Pairs with Security.evtx for correlation.",
	},
	{
		Label:    `PowerShell op log`,
		Path:     `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryLogs,
		Notes:    "PowerShell script-block and pipeline execution log. High-value for attacker activity.",
	},
	// ── Windows — config ───────────────────────────────────────────────────
	{
		Label:    `hosts file`,
		Path:     `C:\Windows\System32\drivers\etc\hosts`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryConfig,
		Notes:    "Local hostname overrides. Should rarely change in a managed fleet.",
	},
	{
		Label:    `NTUSER.DAT (per-user)`,
		Path:     `C:\Users`,
		Platform: CarvePlatformWindows,
		Category: CarveCategoryConfig,
		Notes:    "Per-user registry hive. Carve a specific user: C:\\Users\\<user>\\NTUSER.DAT (locked while user is logged in).",
	},
}
