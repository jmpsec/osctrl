package vulns

import "github.com/jmpsec/osctrl/pkg/posture"

const inventoryInterval = 86400 // daily

var inventoryQueries = map[string]string{
	CategoryOS:     "SELECT name, version, major, minor, platform, platform_like, codename FROM os_version",
	CategoryDeb:    "SELECT name, version, source, arch FROM deb_packages WHERE status = 'install ok installed'",
	CategoryRPM:    "SELECT name, version, release, epoch, arch, source, vendor FROM rpm_packages",
	CategoryPython: "SELECT name, version, path FROM python_packages",
	CategoryNPM:    "SELECT name, version, path FROM npm_packages",
}

func profile(id, name, platform string, categories ...string) posture.PostureProfile {
	p := posture.PostureProfile{
		ID:          id,
		Name:        name,
		Description: "Daily software inventory snapshots for vulnerability matching. Package lists stay inside the deployment.",
		Platform:    platform,
		Queries:     map[string]posture.ProfileQuery{},
	}
	for _, c := range categories {
		p.Queries[c] = posture.ProfileQuery{
			QueryName: QueryPrefix + c,
			Query:     inventoryQueries[c],
			Interval:  inventoryInterval,
			Platform:  platform,
			Snapshot:  true,
		}
	}
	return p
}

// Profiles returns the inventory schedules, one per platform, in the shape
// posture profiles use so the existing apply workflow can merge them.
func Profiles() []posture.PostureProfile {
	return []posture.PostureProfile{
		profile("vuln-linux", "Vulnerability inventory (Linux)", "linux", CategoryOS, CategoryDeb, CategoryRPM, CategoryPython, CategoryNPM),
		profile("vuln-darwin", "Vulnerability inventory (macOS)", "darwin", CategoryOS, CategoryPython, CategoryNPM),
		profile("vuln-windows", "Vulnerability inventory (Windows)", "windows", CategoryOS, CategoryPython, CategoryNPM),
	}
}

// Profile returns one profile by id.
func Profile(id string) (posture.PostureProfile, bool) {
	for _, p := range Profiles() {
		if p.ID == id {
			return p, true
		}
	}
	return posture.PostureProfile{}, false
}
