package handlers

import (
	"errors"
	"fmt"

	"github.com/jmpsec/osctrl/pkg/auth"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/rs/zerolog/log"
)

// ErrAuthUserRejected is returned by resolveFederatedUser when the
// identity cannot be turned into a usable AdminUser. Callers should
// not surface this to clients verbatim — return a generic
// "authentication failed" error to avoid leaking which path
// rejected (timing-oracle and information-disclosure defense).
var ErrAuthUserRejected = errors.New("auth: identity cannot be resolved to an AdminUser")

// resolveFederatedUser maps a federated identity (OIDC, SAML
// eventually) to an existing AdminUser. Policy mirrors legacy
// admin's:
//
//  1. Username exists in admin_users → use that row.
//  2. Else if `jitProvision` is true on the env's provider config
//     → create a new AdminUser with zero env permissions. The
//     operator must grant access manually.
//  3. Else → reject.
//
// When JIT creates a new user and no admin users exist yet (first-run
// bootstrap), the new user is created with admin=true so the operator
// can manage the system immediately. When admin users already exist,
// the new user is admin=false — an existing admin must promote them.
//
// Threat T16 (privilege escalation via JIT): the JIT path
// only sets admin=true when CountAdmins() returns 0. On any system
// that already has an admin, JIT users are non-admin. There is no
// path in this function that produces a row with admin=true on an
// already-administered system.
//
// Threat T25 (mass-assignment via JIT): the function never
// deserializes ResolvedIdentity directly into the struct. Field-
// by-field copy with explicit flags.
//
// Threat T15 (account takeover): if a username exists, this
// function returns that row regardless of whether it was originally
// created via password-login or via federated JIT. v1 has no
// "linking" of OIDC subjects to AdminUser rows — same-name match is
// enough. This is the legacy admin's behavior; it matches existing
// operator expectations and avoids needing a new table. The
// trade-off is documented in the spec.
func (h *HandlersApi) resolveFederatedUser(identity auth.ResolvedIdentity, jitProvision bool, authSource string) (users.AdminUser, error) {
	if identity.PreferredUsername == "" {
		// Defensive — sanitizeUsername in pkg/auth/oidc already
		// catches empty values, but never trust upstream.
		return users.AdminUser{}, fmt.Errorf("%w: empty username", ErrAuthUserRejected)
	}
	if exists, existing := h.Users.ExistsGet(identity.PreferredUsername); exists {
		if existing.AuthSource == "" {
			return users.AdminUser{}, fmt.Errorf("%w: username %q is a local account and cannot be claimed by federated login",
				ErrAuthUserRejected, identity.PreferredUsername)
		}
		// Allow cross-protocol federated login (oidc↔saml) — same IdP
		// may serve both protocols. Update the stamp to the current one.
		if existing.AuthSource != authSource {
			if err := h.Users.ChangeAuthSource(existing.Username, authSource); err != nil {
				return users.AdminUser{}, fmt.Errorf("%w: updating auth source: %v", ErrAuthUserRejected, err)
			}
			existing.AuthSource = authSource
		}
		return existing, nil
	}
	if !jitProvision {
		return users.AdminUser{}, fmt.Errorf("%w: user not provisioned and jitProvision disabled", ErrAuthUserRejected)
	}
	// JIT: build a new AdminUser. When no admin users exist yet
	// (first-run bootstrap scenario), the new user is created as
	// admin=true so the operator can immediately manage the system
	// after their first federated login. When admin users already
	// exist, the new user is created as admin=false — the existing
	// admin must promote them manually. This prevents a federated
	// user from self-escalating to admin on a system that already
	// has an operator.
	adminCount, err := h.Users.CountAdmins()
	if err != nil {
		return users.AdminUser{}, fmt.Errorf("%w: counting admins: %w", ErrAuthUserRejected, err)
	}
	makeAdmin := adminCount == 0
	if makeAdmin {
		log.Info().Str("username", identity.PreferredUsername).Int64("existing_admins", adminCount).
			Msg("JIT-provisioning first admin user via federated login")
	}
	u, err := h.Users.New(
		identity.PreferredUsername, // username
		"",                         // password (empty: forces SSO-only)
		identity.Email,             // email (informational)
		identity.Name,              // fullname (display)
		makeAdmin,                  // admin = true only when no admins exist
		false,                      // service = false
	)
	if err != nil {
		return users.AdminUser{}, fmt.Errorf("%w: new user: %v", ErrAuthUserRejected, err)
	}
	// Tag the row with the provider type (oidc / saml) so the Users
	// page can display the right badge. Purely informational; the auth
	// flow itself doesn't gate on this field.
	u.AuthSource = authSource
	if err := h.Users.Create(u); err != nil {
		return users.AdminUser{}, fmt.Errorf("%w: create user: %v", ErrAuthUserRejected, err)
	}
	return u, nil
}
