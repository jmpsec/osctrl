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

// federatedPolicy carries the per-provider switches that govern how a
// federated identity may become an AdminUser. They are grouped into a struct
// because two adjacent bool arguments at a call site are indistinguishable,
// and silently swapping them would turn a security control off.
type federatedPolicy struct {
	// authSource stamps the resolved row: "oidc" or "saml".
	authSource string
	// jitProvision allows creating a brand-new AdminUser for a username
	// that does not exist yet.
	jitProvision bool
	// linkLocalAccounts allows a federated identity to claim an existing
	// LOCAL (password) account with the same username. Off by default —
	// see the threat note on resolveFederatedUser.
	linkLocalAccounts bool
}

// resolveFederatedUser maps a federated identity (OIDC, SAML
// eventually) to an existing AdminUser. Policy mirrors legacy
// admin's:
//
//  1. Username exists in admin_users → use that row. When the row is a
//     local password account, it is claimed only if
//     `policy.linkLocalAccounts` is set (see threat T15 below).
//  2. Else if `policy.jitProvision` is true on the env's provider config
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
// Threat T15 (account takeover): a federated identity whose username
// matches an existing LOCAL password account does NOT get that account by
// default — otherwise anyone who can make the IdP assert the username
// "admin" would inherit the local admin's privileges. Claiming a local
// account requires the operator to opt in per provider with
// linkLocalAccounts, which is a deliberate delegation of trust: with it on,
// whoever controls the IdP's username namespace can claim any same-named
// local account, admin rows included. Rows already stamped with an
// AuthSource were created by federated login in the first place, so
// cross-protocol re-matching (oidc↔saml, same IdP) stays unconditional.
func (h *HandlersApi) resolveFederatedUser(identity auth.ResolvedIdentity, policy federatedPolicy, clientIP string) (users.AdminUser, error) {
	if identity.PreferredUsername == "" {
		// Defensive — sanitizeUsername in pkg/auth/oidc already
		// catches empty values, but never trust upstream.
		return users.AdminUser{}, fmt.Errorf("%w: empty username", ErrAuthUserRejected)
	}
	if exists, existing := h.Users.ExistsGet(identity.PreferredUsername); exists {
		if existing.AuthSource == "" && !policy.linkLocalAccounts {
			return users.AdminUser{}, fmt.Errorf("%w: username %q is a local password account; set linkLocalAccounts on the %s provider to let federated login claim it",
				ErrAuthUserRejected, identity.PreferredUsername, policy.authSource)
		}
		// Two cases reach here and both end with the row stamped for the
		// protocol that just authenticated:
		//   - a local account the operator has allowed to be linked;
		//   - a federated row logging in over the other protocol
		//     (oidc↔saml), since one IdP may serve both.
		if existing.AuthSource != policy.authSource {
			linkedLocal := existing.AuthSource == ""
			if err := h.Users.ChangeAuthSource(existing.Username, policy.authSource); err != nil {
				return users.AdminUser{}, fmt.Errorf("%w: updating auth source: %v", ErrAuthUserRejected, err)
			}
			existing.AuthSource = policy.authSource
			if linkedLocal {
				// A local account changing hands is worth a loud record:
				// from here on the IdP, not the stored password, controls
				// who gets in — including if this row is an admin.
				log.Warn().Str("username", existing.Username).Str("auth_source", policy.authSource).
					Bool("admin", existing.Admin).
					Msg("federated login claimed an existing local password account (linkLocalAccounts is enabled)")
				if h.AuditLog != nil {
					h.AuditLog.SettingsAction(existing.Username,
						fmt.Sprintf("local account linked to %s federated login", policy.authSource), clientIP)
				}
			}
		}
		return existing, nil
	}
	if !policy.jitProvision {
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
	u.AuthSource = policy.authSource
	if err := h.Users.Create(u); err != nil {
		return users.AdminUser{}, fmt.Errorf("%w: create user: %v", ErrAuthUserRejected, err)
	}
	return u, nil
}
