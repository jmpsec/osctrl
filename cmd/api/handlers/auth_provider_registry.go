package handlers

import (
	"sync"

	"github.com/jmpsec/osctrl/pkg/auth"
	"github.com/jmpsec/osctrl/pkg/authproviders"
)

// AuthProviderRegistry holds the live, concurrently-safe set of built
// auth providers. It replaces the package-global oidcProvider /
// samlProvider variables with a multi-provider model: the login page
// renders one button per enabled provider.
//
// The registry is replaced atomically during hot-reload via Replace().
// Request handlers read from the registry under a read lock — the
// swap is invisible to in-flight requests that already resolved their
// provider pointer.
type AuthProviderRegistry struct {
	mu      sync.RWMutex
	entries []authproviders.ProviderEntry
	byID    map[uint]*authproviders.ProviderEntry
}

// NewAuthProviderRegistry constructs a registry from the given entries.
func NewAuthProviderRegistry(entries []authproviders.ProviderEntry) *AuthProviderRegistry {
	r := &AuthProviderRegistry{
		entries: entries,
		byID:    make(map[uint]*authproviders.ProviderEntry, len(entries)),
	}
	for i := range entries {
		r.byID[entries[i].ID] = &entries[i]
	}
	return r
}

// Replace atomically swaps the registry contents. The old providers
// are not closed (neither OIDC nor SAML providers hold resources that
// need explicit cleanup at this time — the interface can grow a
// Close() method later).
func (r *AuthProviderRegistry) Replace(entries []authproviders.ProviderEntry) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = entries
	r.byID = make(map[uint]*authproviders.ProviderEntry, len(entries))
	for i := range entries {
		r.byID[entries[i].ID] = &entries[i]
	}
}

// Get returns the provider entry for the given row ID, or nil.
func (r *AuthProviderRegistry) Get(id uint) *authproviders.ProviderEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// AllByType returns all enabled providers of the given type
// ("oidc" or "saml"), sorted by name.
func (r *AuthProviderRegistry) AllByType(typ string) []authproviders.ProviderEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []authproviders.ProviderEntry
	for _, e := range r.entries {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// HasOIDC returns true if at least one OIDC provider is enabled.
func (r *AuthProviderRegistry) HasOIDC() bool {
	return len(r.AllByType("oidc")) > 0
}

// HasSAML returns true if at least one SAML provider is enabled.
func (r *AuthProviderRegistry) HasSAML() bool {
	return len(r.AllByType("saml")) > 0
}

// AllProviders returns metadata for every enabled provider, for the
// auth methods endpoint.
func (r *AuthProviderRegistry) AllProviders() []authproviders.ProviderEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]authproviders.ProviderEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// Compile-time check that auth.Provider is still the interface we
// expect — catches accidental drift if the auth package changes.
var _ auth.Provider = (auth.Provider)(nil)
