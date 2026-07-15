package posture

import (
	"encoding/json"
	"sort"
)

// PostureProfile is a named set of posture check queries that an operator
// can merge into an environment's schedule config. Each profile targets a
// specific node type and platform with checks tailored to that
// environment's compliance requirements.
type PostureProfile struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Platform    string                  `json:"platform"`
	Queries     map[string]ProfileQuery `json:"queries"`
}

// ProfileQuery is a single scheduled query within a posture profile.
type ProfileQuery struct {
	Query    string `json:"query"`
	Interval int    `json:"interval"`
	Platform string `json:"platform,omitempty"`
	Snapshot bool   `json:"snapshot"`
}

// ToScheduleEntries converts a profile's queries into a JSON map suitable
// for pasting into the environment's schedule config section.
func (p PostureProfile) ToScheduleEntries() (map[string]map[string]interface{}, error) {
	out := make(map[string]map[string]interface{}, len(p.Queries))
	for name, q := range p.Queries {
		entry := map[string]interface{}{
			"query":    q.Query,
			"interval": q.Interval,
			"snapshot": q.Snapshot,
		}
		if q.Platform != "" {
			entry["platform"] = q.Platform
		}
		out[QueryPrefix+name] = entry
	}
	return out, nil
}

// ToScheduleJSON returns the schedule entries as a pretty-printed JSON string.
func (p PostureProfile) ToScheduleJSON() (string, error) {
	entries, err := p.ToScheduleEntries()
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// AllProfiles returns every predefined posture profile, sorted by name.
func AllProfiles() []PostureProfile {
	profiles := []PostureProfile{
		WindowsServerProfile(),
		LinuxServerProfile(),
		MacOSLaptopProfile(),
		WindowsLaptopProfile(),
		LinuxLaptopProfile(),
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles
}

// GetProfile returns a single profile by ID, or nil if not found.
func GetProfile(id string) *PostureProfile {
	for _, p := range AllProfiles() {
		if p.ID == id {
			return &p
		}
	}
	return nil
}

// -----------------------------------------------------------------------
// Windows Servers
// -----------------------------------------------------------------------

func WindowsServerProfile() PostureProfile {
	return PostureProfile{
		ID:          "win-server",
		Name:        "Windows Servers",
		Platform:    "windows",
		Description: "Posture checks for Windows production servers: installed programs, real users, disk encryption, running services, scheduled tasks, autorun entries, listening ports, and event log errors. All queries run once per day.",
		Queries: map[string]ProfileQuery{
			"packages_windows": {
				Query:    "SELECT name, version, publisher, install_date FROM programs ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"users": {
				Query:    "SELECT username, uid, gid, shell, type FROM users WHERE shell IS NOT NULL AND shell != '' AND shell NOT LIKE '%/nologin' AND shell NOT LIKE '%/false' ORDER BY username",
				Interval: 86400, Snapshot: true,
			},
			"disk_encryption": {
				Query:    "SELECT name, encrypted, type FROM disk_encryption WHERE name IS NOT NULL",
				Interval: 86400, Snapshot: true,
			},
			"listening_ports": {
				Query:    "SELECT pid, port, address, family, path FROM listening_ports WHERE port != 0 ORDER BY port",
				Interval: 86400, Snapshot: true,
			},
			"windows_services": {
				Query:    "SELECT name, display_name, status, start_type, path FROM services WHERE status = 'Running' ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"windows_scheduled_tasks": {
				Query:    "SELECT name, state, action, path, enabled FROM scheduled_tasks WHERE enabled = 1 ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"autorun": {
				Query:    "SELECT name, path, source FROM autoexec ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"patches": {
				Query:    "SELECT hotfix_id, installed_on, description FROM patches ORDER BY installed_on DESC",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
		},
	}
}

// -----------------------------------------------------------------------
// Linux Servers
// -----------------------------------------------------------------------

func LinuxServerProfile() PostureProfile {
	return PostureProfile{
		ID:          "linux-server",
		Name:        "Linux Servers",
		Platform:    "linux",
		Description: "Posture checks for Linux production servers: deb/rpm packages, real users, disk encryption, listening ports, cron jobs, systemd timers, kernel modules, SUID binaries, and SSH keys. All queries run once per day.",
		Queries: map[string]ProfileQuery{
			"packages_deb": {
				Query:    "SELECT name, version, revision, source AS repo FROM deb_packages ORDER BY name",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"packages_rpm": {
				Query:    "SELECT name, version, release, '' AS repo FROM rpm_packages ORDER BY name",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"users": {
				Query:    "SELECT username, uid, gid, shell, type FROM users WHERE shell IS NOT NULL AND shell != '' AND shell NOT LIKE '%/nologin' AND shell NOT LIKE '%/false' ORDER BY username",
				Interval: 86400, Snapshot: true,
			},
			"disk_encryption": {
				Query:    "SELECT name, encrypted, type FROM disk_encryption WHERE name IS NOT NULL",
				Interval: 86400, Snapshot: true,
			},
			"listening_ports": {
				Query:    "SELECT pid, port, address, family, path FROM listening_ports WHERE port != 0 ORDER BY port",
				Interval: 86400, Snapshot: true,
			},
			"cron_jobs": {
				Query:    "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab ORDER BY path, event",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"systemd_timers": {
				Query:    "SELECT id, active_state, sub_state, load_state FROM systemd_units WHERE active_state = 'active' ORDER BY id",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"kernel_modules": {
				Query:    "SELECT name, size, used_by, status FROM kernel_modules WHERE status = 'Live' ORDER BY name",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"suid_binaries": {
				Query:    "SELECT path, permissions, username, groupname FROM suid_bin ORDER BY path",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"ssh_keys": {
				Query:    "SELECT uid, key_file, key, algorithm FROM authorized_keys ORDER BY uid",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
		},
	}
}

// -----------------------------------------------------------------------
// macOS Laptops
// -----------------------------------------------------------------------

func MacOSLaptopProfile() PostureProfile {
	return PostureProfile{
		ID:          "macos-laptop",
		Name:        "macOS Laptops",
		Platform:    "darwin",
		Description: "Posture checks for corporate macOS laptops: Homebrew packages, installed apps, real users, disk encryption, startup items, browser extensions, WiFi networks, SSH keys, and file sharing preferences. All queries run once per day.",
		Queries: map[string]ProfileQuery{
			"packages_brew": {
				Query:    "SELECT name, version, type FROM homebrew_packages ORDER BY name",
				Interval: 86400, Platform: "darwin", Snapshot: true,
			},
			"packages_apps": {
				Query:    "SELECT name, bundle_identifier AS bundle_id, bundle_short_version AS version FROM apps ORDER BY name",
				Interval: 86400, Platform: "darwin", Snapshot: true,
			},
			"users": {
				Query:    "SELECT username, uid, gid, shell, type FROM users WHERE shell IS NOT NULL AND shell != '' AND shell NOT LIKE '%/nologin' AND shell NOT LIKE '%/false' ORDER BY username",
				Interval: 86400, Snapshot: true,
			},
			"disk_encryption": {
				Query:    "SELECT name, encrypted, type FROM disk_encryption WHERE name IS NOT NULL",
				Interval: 86400, Snapshot: true,
			},
			"startup_items": {
				Query:    "SELECT path, name, type, status, source FROM startup_items ORDER BY name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_chrome": {
				Query:    "SELECT uid, name, identifier, version FROM chrome_extensions ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_firefox": {
				Query:    "SELECT uid, name, identifier, version FROM firefox_addons ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"wifi_networks": {
				Query:    "SELECT ssid, security_type, last_connected, auto_join FROM wifi_networks ORDER BY ssid",
				Interval: 86400, Platform: "darwin", Snapshot: true,
			},
			"ssh_keys": {
				Query:    "SELECT uid, key_file, key, algorithm FROM authorized_keys ORDER BY uid",
				Interval: 86400, Snapshot: true,
			},
			"file_sharing": {
				Query:    "SELECT file_sharing, screen_sharing, remote_login, remote_management, printer_sharing, internet_sharing FROM sharing_preferences",
				Interval: 86400, Platform: "darwin", Snapshot: true,
			},
		},
	}
}

// -----------------------------------------------------------------------
// Windows Laptops
// -----------------------------------------------------------------------

func WindowsLaptopProfile() PostureProfile {
	return PostureProfile{
		ID:          "win-laptop",
		Name:        "Windows Laptops",
		Platform:    "windows",
		Description: "Posture checks for corporate Windows laptops: installed programs, real users, disk encryption, startup items, browser extensions, autorun entries, WiFi networks, and patches. All queries run once per day.",
		Queries: map[string]ProfileQuery{
			"packages_windows": {
				Query:    "SELECT name, version, publisher, install_date FROM programs ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"users": {
				Query:    "SELECT username, uid, gid, shell, type FROM users WHERE shell IS NOT NULL AND shell != '' AND shell NOT LIKE '%/nologin' AND shell NOT LIKE '%/false' ORDER BY username",
				Interval: 86400, Snapshot: true,
			},
			"disk_encryption": {
				Query:    "SELECT name, encrypted, type FROM disk_encryption WHERE name IS NOT NULL",
				Interval: 86400, Snapshot: true,
			},
			"startup_items": {
				Query:    "SELECT path, name, type, status, source FROM startup_items ORDER BY name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_chrome": {
				Query:    "SELECT uid, name, identifier, version FROM chrome_extensions ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_firefox": {
				Query:    "SELECT uid, name, identifier, version FROM firefox_addons ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"autorun": {
				Query:    "SELECT name, path, source FROM autoexec ORDER BY name",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"wifi_networks": {
				Query:    "SELECT ssid, security_type, last_connected, auto_join FROM wifi_networks ORDER BY ssid",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
			"patches": {
				Query:    "SELECT hotfix_id, installed_on, description FROM patches ORDER BY installed_on DESC",
				Interval: 86400, Platform: "windows", Snapshot: true,
			},
		},
	}
}

// -----------------------------------------------------------------------
// Linux Laptops
// -----------------------------------------------------------------------

func LinuxLaptopProfile() PostureProfile {
	return PostureProfile{
		ID:          "linux-laptop",
		Name:        "Linux Laptops",
		Platform:    "linux",
		Description: "Posture checks for corporate Linux laptops: deb/rpm packages, real users, disk encryption, startup items, browser extensions, SSH keys, and WiFi networks. All queries run once per day.",
		Queries: map[string]ProfileQuery{
			"packages_deb": {
				Query:    "SELECT name, version, revision, source AS repo FROM deb_packages ORDER BY name",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"packages_rpm": {
				Query:    "SELECT name, version, release, '' AS repo FROM rpm_packages ORDER BY name",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
			"users": {
				Query:    "SELECT username, uid, gid, shell, type FROM users WHERE shell IS NOT NULL AND shell != '' AND shell NOT LIKE '%/nologin' AND shell NOT LIKE '%/false' ORDER BY username",
				Interval: 86400, Snapshot: true,
			},
			"disk_encryption": {
				Query:    "SELECT name, encrypted, type FROM disk_encryption WHERE name IS NOT NULL",
				Interval: 86400, Snapshot: true,
			},
			"startup_items": {
				Query:    "SELECT path, name, type, status, source FROM startup_items ORDER BY name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_chrome": {
				Query:    "SELECT uid, name, identifier, version FROM chrome_extensions ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"browser_extensions_firefox": {
				Query:    "SELECT uid, name, identifier, version FROM firefox_addons ORDER BY uid, name",
				Interval: 86400, Snapshot: true,
			},
			"ssh_keys": {
				Query:    "SELECT uid, key_file, key, algorithm FROM authorized_keys ORDER BY uid",
				Interval: 86400, Platform: "linux", Snapshot: true,
			},
		},
	}
}
