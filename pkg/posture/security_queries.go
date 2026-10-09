package posture

// withSecurityChecks adds small daily snapshots to the existing platform
// profiles. Installation seeds missing checks, but never rewrites an operator's
// saved environment schedule or existing check settings.
func withSecurityChecks(profile PostureProfile) PostureProfile {
	queries := map[string]string{
		"secure_boot": "SELECT secure_boot FROM secureboot",
	}
	switch profile.Platform {
	case "darwin":
		queries["macos_firewall"] = "SELECT global_state FROM alf"
		queries["gatekeeper"] = "SELECT assessments_enabled FROM gatekeeper"
		queries["system_integrity"] = "SELECT config_flag, enabled FROM sip_config WHERE config_flag = 'sip'"
		queries["screen_lock"] = "SELECT enabled, grace_period FROM screenlock"
	case "linux":
		queries["selinux"] = "SELECT key, value FROM selinux_settings WHERE scope = '' AND key = 'enforce'"
		queries["apparmor"] = "SELECT name, mode FROM apparmor_profiles ORDER BY name"
		queries["linux_aslr"] = "SELECT name, current_value FROM system_controls WHERE name = 'kernel.randomize_va_space'"
		queries["audit_service"] = "SELECT id AS name, active_state AS state FROM systemd_units WHERE id = 'auditd.service'"
	case "windows":
		queries["password_storage"] = "SELECT clear_text_password FROM security_profile_info"
		queries["audit_service"] = "SELECT name, status AS state FROM services WHERE name = 'EventLog'"
		// WscGetSecurityProviderHealth has no supported Windows Server version.
		if profile.ID == "win-laptop" {
			queries["windows_firewall"] = "SELECT firewall FROM windows_security_center"
			queries["windows_antivirus"] = "SELECT antivirus FROM windows_security_center"
			queries["windows_updates"] = "SELECT autoupdate FROM windows_security_center"
			queries["windows_uac"] = "SELECT user_account_control FROM windows_security_center"
		}
	}
	for category, query := range queries {
		profile.Queries[category] = ProfileQuery{
			Query: query, Platform: profile.Platform, Interval: 86400, Snapshot: true,
		}
	}
	return profile
}
