package geoip

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog/log"
)

// GeoIPResolver resolves IP addresses to ISO 3166-1 alpha-2 country codes
// using a MaxMind DB (.mmdb) file via the oschwald/maxminddb-golang library.
// A nil pointer or one opened with an empty path is a safe no-op — Lookup
// always returns "".
type GeoIPResolver struct {
	mu       sync.RWMutex
	reader   *maxminddb.Reader
	cacheTTL time.Duration
	cacheMu  sync.RWMutex
	cache    map[string]cacheEntry
}

type cacheEntry struct {
	code      string
	expiresAt time.Time
}

// New opens the mmdb file at path. If path is empty, returns nil (feature disabled).
func New(path string) (*GeoIPResolver, error) {
	if path == "" {
		return nil, nil
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: cannot open mmdb %s: %w", path, err)
	}
	g := &GeoIPResolver{
		reader:   reader,
		cacheTTL: 24 * time.Hour,
		cache:    make(map[string]cacheEntry, 256),
	}
	log.Info().
		Str("path", path).
		Str("db_type", reader.Metadata.DatabaseType).
		Int("node_count", int(reader.Metadata.NodeCount)).
		Msg("GeoIP resolver loaded")
	return g, nil
}

// Close releases the mmdb file handle.
func (g *GeoIPResolver) Close() {
	if g == nil || g.reader == nil {
		return
	}
	_ = g.reader.Close()
}

// Lookup resolves an IP address string to an ISO 3166-1 alpha-2 country code.
// Returns "" if the resolver is nil, the IP is private/invalid, or no country is found.
// Results are cached for 24 hours — IPs rarely change country, and the cache
// avoids re-walking the mmdb binary tree for the same node on every page load.
func (g *GeoIPResolver) Lookup(ipStr string) string {
	if g == nil || g.reader == nil {
		return ""
	}

	// Fast path: check the cache first.
	g.cacheMu.RLock()
	if entry, ok := g.cache[ipStr]; ok && time.Now().Before(entry.expiresAt) {
		g.cacheMu.RUnlock()
		return entry.code
	}
	g.cacheMu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return ""
	}

	// Slow path: mmdb tree walk, then cache the result.
	code := g.lookupTree(ip)
	g.cacheMu.Lock()
	g.cache[ipStr] = cacheEntry{code: code, expiresAt: time.Now().Add(g.cacheTTL)}
	g.cacheMu.Unlock()
	return code
}

func (g *GeoIPResolver) lookupTree(ip net.IP) string {
	var result struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if err := g.reader.Lookup(ip, &result); err != nil {
		return ""
	}
	if result.Country.ISOCode != "" {
		return result.Country.ISOCode
	}
	return result.RegisteredCountry.ISOCode
}
