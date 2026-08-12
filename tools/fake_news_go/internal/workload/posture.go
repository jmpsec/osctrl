package workload

import (
	"fmt"
	"math/rand"
)

// PostureLevel controls the kind of fake posture data generated.
type PostureLevel string

const (
	PostureLevelNone     PostureLevel = ""
	PostureLevelGood     PostureLevel = "good"
	PostureLevelModerate PostureLevel = "moderate"
	PostureLevelPoor     PostureLevel = "poor"
)

// PostureQueryPrefix mirrors pkg/posture.DefaultQueryPrefix.
const PostureQueryPrefix = "osctrl:posture:"

// PostureQuery is a fake posture query definition.
type PostureQuery struct {
	Name     string
	Columns  []string
	Generate func(level PostureLevel, r *rand.Rand) []map[string]interface{}
}

// PostureQueries defines the set of posture queries the tool will send.
// Category names match what pkg/posture/scoring.go expects so the scoring
// engine evaluates them correctly.
var PostureQueries = []PostureQuery{
	{
		Name:    "packages_deb",
		Columns: []string{"name", "version", "revision", "repo"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			count := 0
			switch level {
			case PostureLevelGood:
				count = r.Intn(20) + 40
			case PostureLevelModerate:
				count = r.Intn(30) + 80
			case PostureLevelPoor:
				count = r.Intn(50) + 150
			}
			results := make([]map[string]interface{}, 0, count)
			for i := 0; i < count; i++ {
				results = append(results, map[string]interface{}{
					"name":     fmt.Sprintf("package-%d", i),
					"version":  fmt.Sprintf("%d.%d.%d", r.Intn(5), r.Intn(20), r.Intn(10)),
					"revision": "1",
					"repo":     "main",
				})
			}
			return results
		},
	},
	{
		Name:    "users",
		Columns: []string{"username", "uid", "gid", "shell"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			// Good: few users, no extra root. Poor: many users, maybe extra root.
			count := 0
			extraRoot := 0
			switch level {
			case PostureLevelGood:
				count = r.Intn(2) + 2
			case PostureLevelModerate:
				count = r.Intn(5) + 5
			case PostureLevelPoor:
				count = r.Intn(10) + 20
				extraRoot = r.Intn(2)
			}
			shells := []string{"/bin/bash", "/bin/sh", "/bin/zsh"}
			nologinShells := []string{"/usr/sbin/nologin", "/bin/false"}
			results := make([]map[string]interface{}, 0, count)
			// Always include root first
			results = append(results, map[string]interface{}{
				"username": "root", "uid": 0, "gid": 0, "shell": "/bin/bash",
			})
			for i := 0; i < extraRoot; i++ {
				results = append(results, map[string]interface{}{
					"username": fmt.Sprintf("root%d", i), "uid": 0, "gid": 0, "shell": "/bin/bash",
				})
			}
			for i := 0; i < count; i++ {
				shell := shells[r.Intn(len(shells))]
				if level == PostureLevelGood && r.Intn(3) == 0 {
					shell = nologinShells[r.Intn(len(nologinShells))]
				}
				results = append(results, map[string]interface{}{
					"username": fmt.Sprintf("user%d", i),
					"uid":      1000 + i,
					"gid":      1000 + i,
					"shell":    shell,
				})
			}
			return results
		},
	},
	{
		Name:    "disk_encryption",
		Columns: []string{"name", "encrypted", "type"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			// Good: all encrypted. Poor: unencrypted.
			encrypted := "1"
			if level == PostureLevelPoor {
				encrypted = "0"
			} else if level == PostureLevelModerate && r.Intn(2) == 0 {
				encrypted = "0"
			}
			return []map[string]interface{}{
				{"name": "/dev/sda1", "encrypted": encrypted, "type": "LUKS1"},
			}
		},
	},
	{
		Name:    "listening_ports",
		Columns: []string{"pid", "port", "protocol", "address"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			count := 0
			switch level {
			case PostureLevelGood:
				count = r.Intn(3) + 2
			case PostureLevelModerate:
				count = r.Intn(10) + 10
			case PostureLevelPoor:
				count = r.Intn(20) + 30
			}
			// Good: only safe ports (22, 443). Poor: include risky ports (23, 21, 3389).
			safePorts := []int{22, 443, 80}
			riskyPorts := []int{23, 21, 3389, 445, 161}
			results := make([]map[string]interface{}, 0, count)
			for i := 0; i < count; i++ {
				port := 0
				if level == PostureLevelPoor && r.Intn(3) == 0 {
					port = riskyPorts[r.Intn(len(riskyPorts))]
				} else {
					port = safePorts[r.Intn(len(safePorts))]
				}
				results = append(results, map[string]interface{}{
					"pid":      r.Intn(50000),
					"port":     port,
					"protocol": []string{"tcp", "udp"}[r.Intn(2)],
					"address":  "0.0.0.0",
				})
			}
			return results
		},
	},
	{
		Name:    "suid_binaries",
		Columns: []string{"path", "permissions", "username", "groupname"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			// Standard SUID binaries that the scoring engine accepts.
			standardSUID := []string{
				"/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
				"/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp",
				"/usr/bin/mount", "/usr/bin/umount",
			}
			// Non-standard SUID that triggers a warning.
			nonStandardSUID := []string{
				"/tmp/custom_suid", "/opt/app/escalate", "/home/user/runme",
				"/var/lib/helper", "/usr/local/bin/elevate",
			}

			count := 0
			nonStandardCount := 0
			switch level {
			case PostureLevelGood:
				count = r.Intn(3) + 5
				nonStandardCount = 0
			case PostureLevelModerate:
				count = r.Intn(5) + 8
				nonStandardCount = r.Intn(3)
			case PostureLevelPoor:
				count = r.Intn(5) + 10
				nonStandardCount = r.Intn(3) + 5
			}

			results := make([]map[string]interface{}, 0, count)
			for i := 0; i < count && i < len(standardSUID); i++ {
				results = append(results, map[string]interface{}{
					"path":        standardSUID[i],
					"permissions": "4755",
					"username":    "root",
					"groupname":   "root",
				})
			}
			for i := 0; i < nonStandardCount && i < len(nonStandardSUID); i++ {
				results = append(results, map[string]interface{}{
					"path":        nonStandardSUID[i],
					"permissions": "4755",
					"username":    "root",
					"groupname":   "root",
				})
			}
			return results
		},
	},
	{
		Name:    "patches",
		Columns: []string{"name", "version"},
		Generate: func(level PostureLevel, r *rand.Rand) []map[string]interface{} {
			// Good: many patches. Poor: few or none.
			count := 0
			switch level {
			case PostureLevelGood:
				count = r.Intn(50) + 100
			case PostureLevelModerate:
				count = r.Intn(30) + 30
			case PostureLevelPoor:
				count = r.Intn(5)
			}
			results := make([]map[string]interface{}, 0, count)
			for i := 0; i < count; i++ {
				results = append(results, map[string]interface{}{
					"name":    fmt.Sprintf("patch-%d", i),
					"version": fmt.Sprintf("KB%d", 500000+r.Intn(999999)),
				})
			}
			return results
		},
	},
}

// GeneratePostureResults generates fake posture query results for all
// categories at the given level. Returns a map of query-name → results.
func GeneratePostureResults(level PostureLevel, r *rand.Rand) map[string][]map[string]interface{} {
	if level == PostureLevelNone {
		return nil
	}
	out := make(map[string][]map[string]interface{})
	for _, q := range PostureQueries {
		fullName := PostureQueryPrefix + q.Name
		out[fullName] = q.Generate(level, r)
	}
	return out
}

// IsValidPostureLevel returns true if the given string is a valid posture level.
func IsValidPostureLevel(s string) bool {
	switch PostureLevel(s) {
	case PostureLevelNone, PostureLevelGood, PostureLevelModerate, PostureLevelPoor:
		return true
	}
	return false
}
