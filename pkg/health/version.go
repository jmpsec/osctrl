package health

import (
	"sync"
	"time"

	"github.com/jmpsec/osctrl/pkg/version"
)

// UpgradeInfo is the upgrade block on the health page.
type UpgradeInfo struct {
	Current   string    `json:"current"`
	Suggested string    `json:"suggested,omitempty"`
	Latest    string    `json:"latest,omitempty"`
	UpToDate  bool      `json:"up_to_date"`
	Checked   bool      `json:"checked"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	MoreInfo  string    `json:"more_information,omitempty"`
	// API and TLS expose the per-service versions behind Skew so the page
	// can name both sides of a mismatch.
	API  string `json:"api_version,omitempty"`
	TLS  string `json:"tls_version,omitempty"`
	Skew bool   `json:"skew"`
}

// VersionCache holds the last upstream version check.
//
// version.RetrieveVersionData performs an external HTTP request, so it must
// never run on the request path. Refresh is called at boot and on a 24h
// ticker; Info only reads memory.
type VersionCache struct {
	mu        sync.RWMutex
	current   string
	data      version.VersionData
	checkedAt time.Time
	checked   bool
}

// NewVersionCache returns a cache for the running build version.
func NewVersionCache(current string) *VersionCache {
	return &VersionCache{current: current}
}

// Set stores version data without fetching. Used by Refresh and by tests.
func (c *VersionCache) Set(data version.VersionData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = data
	c.checkedAt = time.Now()
	c.checked = true
}

// Refresh fetches upstream version data. Errors are returned, not stored: a
// failed check leaves the previous answer in place rather than blanking the
// page because stats.osctrl.net was briefly unreachable.
func (c *VersionCache) Refresh(url string) error {
	data, err := version.RetrieveVersionData(url)
	if err != nil {
		return err
	}
	c.Set(*data)
	return nil
}

// Info renders the upgrade block. tlsVersion comes from the heartbeat row and
// may be empty when osctrl-tls is not reporting.
func (c *VersionCache) Info(tlsVersion string) UpgradeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info := UpgradeInfo{
		Current: c.current,
		Checked: c.checked,
		API:     c.current,
		TLS:     tlsVersion,
		Skew:    tlsVersion != "" && tlsVersion != c.current,
	}
	if c.checked {
		info.Suggested = c.data.SuggestedRelease
		info.Latest = c.data.LatestRelease
		info.MoreInfo = c.data.MoreInformation
		info.CheckedAt = c.checkedAt
		info.UpToDate = version.CheckSuggestedRelease(c.data.SuggestedRelease)
	}
	return info
}
