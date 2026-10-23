package osqueryversions

import "time"

// Reasons Resolve gives for not upgrading; "" means upgrade.
const (
	ReasonNoTarget             = "no_target"
	ReasonAheadOfTarget        = "ahead_of_target"
	ReasonNoDigestForTarget    = "no_digest_for_target"
	ReasonNoDigestForInstalled = "no_digest_for_installed"
	ReasonUnsupportedPlatform  = "unsupported_platform"
)

// ResolveInput is what a node reports plus its identity.
type ResolveInput struct {
	EnvironmentID                                      uint
	NodeUUID, Platform, Arch, Format, InstalledVersion string
}

// Ref is a version with the SHA-256 of its package.
type Ref struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Resolution is the answer for one node. Target and Previous are set only when Reason is "".
type Resolution struct {
	Reason, Source, RequestID string
	Target, Previous          *Ref
}

// Resolve decides what a node should do: the unexpired pin wins over the
// environment target. Versions are matched by exact string, as stored.
func (m *Manager) Resolve(in ResolveInput, now time.Time) (Resolution, error) {
	arch := in.Arch
	if in.Platform == "darwin" && in.Format == "pkg" && (arch == "amd64" || arch == "arm64") {
		arch = "universal"
	}
	if ValidEntry(in.Platform, arch, in.Format, strings64) != nil {
		return Resolution{Reason: ReasonUnsupportedPlatform}, nil
	}
	var res Resolution
	pin, err := m.GetPin(in.NodeUUID)
	if err != nil {
		return res, err
	}
	var version string
	if pin != nil && pin.EnvironmentID == in.EnvironmentID && !pin.Expired(now) {
		version, res.Source, res.RequestID = pin.Version, "pin", pin.RequestID
	} else {
		t, err := m.GetEnvTarget(in.EnvironmentID)
		if err != nil {
			return res, err
		}
		if t == nil {
			return Resolution{Reason: ReasonNoTarget}, nil
		}
		version, res.Source, res.RequestID = t.Version, "environment", t.RequestID
	}
	installedOK := ValidVersion(in.InstalledVersion)
	if installedOK {
		if c, err := Compare(in.InstalledVersion, version); err == nil && c >= 0 {
			return Resolution{Reason: ReasonAheadOfTarget, Source: res.Source, RequestID: res.RequestID}, nil
		}
	}
	target, err := m.digest(version, in.Platform, arch, in.Format)
	if err != nil {
		return res, err
	}
	if target == nil {
		return Resolution{Reason: ReasonNoDigestForTarget, Source: res.Source, RequestID: res.RequestID}, nil
	}
	var prev *Ref
	if installedOK {
		if prev, err = m.digest(in.InstalledVersion, in.Platform, arch, in.Format); err != nil {
			return res, err
		}
	}
	if prev == nil {
		return Resolution{Reason: ReasonNoDigestForInstalled, Source: res.Source, RequestID: res.RequestID}, nil
	}
	res.Target, res.Previous = target, prev
	return res, nil
}

// digest returns the library digest for one key, or nil when absent.
func (m *Manager) digest(version, platform, arch, format string) (*Ref, error) {
	var e DigestEntry
	err := m.db.Where("version = ? AND platform = ? AND arch = ? AND format = ?", version, platform, arch, format).Limit(1).Find(&e).Error
	if err != nil || e.ID == 0 {
		return nil, err
	}
	return &Ref{Version: e.Version, SHA256: e.SHA256}, nil
}

const strings64 = "0000000000000000000000000000000000000000000000000000000000000000"
