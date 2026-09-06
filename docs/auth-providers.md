# Configuring Identity Providers for osctrl

osctrl-api supports three authentication methods simultaneously: local
password, OIDC, and SAML 2.0. This guide covers IdP-side configuration
for the two federated protocols and documents the non-obvious gotchas
for each tested provider.

## Table of contents

- [Configuration modes](#configuration-modes)
- [Database-backed provider editor](#database-backed-provider-editor)
- [Environment variables reference](#environment-variables-reference)
- [Username rules](#username-rules)
- [Linking existing local accounts](#linking-existing-local-accounts)
- [Multi-factor authentication](#multi-factor-authentication)
- [OIDC](#oidc)
  - [Generic OIDC setup](#generic-oidc-setup)
  - [Keycloak](#keycloak-oidc)
  - [Auth0](#auth0-oidc)
  - [Okta](#okta-oidc)
  - [Microsoft Entra ID](#entra-id-oidc)
- [SAML 2.0](#saml-20)
  - [Generic SAML setup](#generic-saml-setup)
  - [Keycloak](#keycloak-saml)
  - [Auth0](#auth0-saml)
- [Logout and IdP session termination](#logout-and-idp-session-termination)
- [Running OIDC and SAML simultaneously](#running-oidc-and-saml-simultaneously)
- [Troubleshooting](#troubleshooting)

---

## Configuration modes

osctrl-api resolves startup settings from **either** flags/environment
variables **or** a YAML file — not both. When `--config` is passed, the YAML
file is the only service-configuration source; environment variables are not
merged into it.

So pick the one that matches how you run the service:

- **Provisioned / systemd deployments** — edit the `saml:` and `oidc:`
  sections of the deployed API YAML file. Native packages install it at
  `/opt/osctrl/config/api.yml`; source provisioning commonly uses
  `config/osctrl-api.yml`. Run
  `osctrl-api config-generate` to emit a fresh file with both sections
  present, or copy them from
  [`deploy/config/api.yml`](../deploy/config/api.yml).
- **Containers or a hand-rolled invocation with no `--config`** — use the
  environment variables below.

The YAML keys are the camelCase equivalents of the flags
(`OIDC_ISSUER_URL` → `oidc.issuerUrl`, `SAML_ACS_URL` → `saml.acsUrl`,
and so on). A complete annotated example of both sections lives in
`deploy/config/api.yml`.

At startup, enabled YAML or flag-based OIDC and SAML definitions are also
seeded into the `auth_providers` table with create-if-missing semantics.
The API builds its provider registry from those rows, but the public login
routes described in this guide remain gated by the resolved `oidc.enabled`
and `saml.enabled` service settings.

---

## Database-backed provider editor

The SPA exposes an administrator-only provider editor when
`service.authProvidersEnabled` / `AUTH_PROVIDERS_ENABLED` is true (the
default). It can create, validate, redact, reveal, update, revert, and delete
OIDC or SAML rows independently of the general service-configuration UI.

The current runtime integration is incomplete:

- Provider discovery advertises database rows with ID-scoped login URLs, but
  `osctrl-api` does not currently register those ID-scoped public login,
  callback, ACS, or metadata routes.
- `POST /api/v1/auth-providers/apply` queues
  `reload-auth-providers` for `osctrl-tls`; TLS does not consume that
  action, and the API has no service-command consumer.

Consequently, use the YAML/flag configuration documented below for working
federated login. Database edits persist, but an API restart alone does not make
new ID-scoped providers usable until the public route wiring is completed.
This limitation is also recorded in [ARCHITECTURE.md](../ARCHITECTURE.md).

---

## Environment variables reference

### OIDC

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ENABLED` | yes | Set `true` to enable the OIDC login surface |
| `OIDC_ISSUER_URL` | yes | Issuer URL (realm root); `/.well-known/openid-configuration` is appended automatically |
| `OIDC_CLIENT_ID` | yes | Client ID registered with the IdP |
| `OIDC_CLIENT_SECRET` | unless PKCE | Client secret; may be empty only when `OIDC_USE_PKCE=true` |
| `OIDC_REDIRECT_URL` | yes | Must match the IdP's allowed callback and end with `/api/v1/auth/oidc/callback` |
| `OIDC_SCOPES` | no | Comma-separated list (default: `openid,profile,email`) |
| `OIDC_USERNAME_CLAIM` | no | id_token claim to use as the osctrl username (default: `preferred_username`; see [Username rules](#username-rules)) |
| `OIDC_GROUPS_CLAIM` | no | id_token claim containing group memberships (default: `groups`) |
| `OIDC_REQUIRED_GROUPS` | no | Comma-separated group names; login is denied unless the user belongs to at least one |
| `OIDC_JIT_PROVISION` | no | Set `true` to auto-create osctrl users on first login (as non-admin) |
| `OIDC_LINK_LOCAL_ACCOUNTS` | no | Set `true` to let an OIDC login claim an existing local password account with the same username (see [Linking existing local accounts](#linking-existing-local-accounts)) |
| `OIDC_USE_PKCE` | no | Set `true` to enable PKCE (S256) for the authorization code flow |

### SAML

| Variable | Required | Description |
|----------|----------|-------------|
| `SAML_ENABLED` | yes | Set `true` to enable the SAML login surface |
| `SAML_IDP_METADATA_URL` | yes | URL to the IdP's SAML metadata XML — fetched once at startup |
| `SAML_ENTITY_ID` | yes | SP Entity ID — must match what the IdP has registered (typically the metadata URL) |
| `SAML_ACS_URL` | yes | Assertion Consumer Service URL — must end with `/api/v1/auth/saml/acs` |
| `SAML_USERNAME_ATTRIBUTE` | no | SAML attribute name whose value becomes the osctrl username; empty = use NameID |
| `SAML_JIT_PROVISION` | no | Set `true` to auto-create osctrl users on first login (as non-admin) |
| `SAML_LINK_LOCAL_ACCOUNTS` | no | Set `true` to let a SAML login claim an existing local password account with the same username (see [Linking existing local accounts](#linking-existing-local-accounts)) |
| `SAML_FORCE_AUTHN` | no | Force re-authentication at the IdP on every login (default: `true`) |
| `SAML_SIGNING_CERT` | no | Path to PEM certificate for signing AuthnRequests |
| `SAML_SIGNING_KEY` | no | Path to PEM RSA private key for signing AuthnRequests |
| `SAML_LOGOUT_URL` | no | IdP session-termination URL; returned to the SPA so it can end the IdP session on logout |

---

## Username rules

A username may take either of two shapes:

- **Plain handle** — `^[a-zA-Z0-9_-]{1,64}$`
- **Email address** — `local@domain.tld`, up to 254 characters

Email is accepted because most IdPs identify people by mailbox. Anything
carrying a character that could survive a sanitization boundary and reach an
audit log, an API path or a query — newlines, NULs, quotes, semicolons,
slashes, spaces, angle brackets — is rejected in both shapes, as are values
that merely look like an email (`al..ice@corp.com`, `alice@corp.com/../root`).

Email usernames are stored **lowercased**. IdPs are not consistent about the
casing they emit for the same mailbox, and without canonicalization
`Jane@corp.com` and `jane@corp.com` would be two separate accounts on
PostgreSQL but collide on MySQL's default collation. Plain handles keep their
case, so existing mixed-case accounts continue to match on login.

| IdP claim/attribute | Typical value | Passes? |
|---------------------|---------------|---------|
| `preferred_username` | `alice` | yes |
| `nickname` | `alice` | yes |
| `email` | `alice@example.com` | yes — stored as `alice@example.com` |
| NameID (email format) | `Alice@Example.com` | yes — stored as `alice@example.com` |
| `sub` (Auth0) | `auth0\|6a0a...` | **no** — contains `\|` |
| `sub` (Keycloak) | `a1b2c3d4-...` | yes — a 36-char UUID fits the plain shape |

**Using `email` as the username claim:** osctrl only accepts the `email` claim
when the IdP also sets `email_verified` to true. An unverified address falls
back to `sub`, so a user who has not proven control of a mailbox cannot claim
an account belonging to whoever owns it.

**Changing this setting on a live deployment** creates *new* accounts rather
than renaming existing ones — the username is the identity. Moving from
`nickname` to `email` means `alice` and `alice@example.com` are two different
users with separate permissions. Migrate deliberately.

---

## Linking existing local accounts

A federated login whose username matches an existing **local password account**
is refused by default:

```
username "jane@corp.com" is a local password account; set linkLocalAccounts on the oidc provider to let federated login claim it
```

This is deliberate. If a same-name match were enough, anyone who can make the
IdP assert the username `admin` would inherit the local `admin` row and all its
privileges. Accounts that were *already* created by federated login carry an
auth source stamp and are matched unconditionally, including across protocols
(a user provisioned via OIDC can sign in via SAML from the same IdP).

To let the IdP adopt accounts you pre-created locally, opt in per provider:

```yaml
oidc:
  linkLocalAccounts: true
saml:
  linkLocalAccounts: true
```

or `OIDC_LINK_LOCAL_ACCOUNTS=true` / `SAML_LINK_LOCAL_ACCOUNTS=true`.

**What this delegates.** With it on, whoever controls the IdP's username
namespace can claim any same-named local account, admin rows included. Enable it
only when you trust the IdP to be authoritative over usernames — which is
usually true for a corporate IdP you administer, and usually false for one that
allows self-registration or spans domains you do not control.

**What happens on the first such login.** The account is stamped with the
protocol that claimed it, the event is written to the audit log and logged at
WARN, and the stored password is left alone. Linking never grants privileges:
a non-admin stays a non-admin, and environment permissions are unchanged.

Because the row is stamped on first use, the flag is only needed for that
initial login — you can turn it back off afterwards and already-linked accounts
keep working.

## Multi-factor authentication

Password (`db`) logins can require a second factor. This applies only to
local password accounts — federated logins are the identity provider's
responsibility, and service accounts authenticate with a long-lived token
rather than interactively, so both are exempt.

Three factor types are supported:

| Factor | What it covers |
| --- | --- |
| Authenticator app (TOTP) | Google Authenticator, Authy, 1Password, Aegis — RFC 6238, 6 digits, 30s |
| Passkeys and security keys (WebAuthn) | YubiKey and other roaming keys, Touch ID / Windows Hello, password-manager passkeys |
| Recovery codes | Ten single-use codes, issued when the first factor is enrolled |

### How a login works

The password step no longer creates a session on its own. When the user has
a factor, `POST /api/v1/login` answers with a challenge instead of a token:

```json
{"mfa_required": true, "challenge": "…", "methods": ["totp", "webauthn", "recovery"]}
```

The client then answers it with one of:

- `POST /api/v1/login/mfa` — `{"challenge": "…", "method": "totp"|"recovery", "code": "…"}`
- `POST /api/v1/login/mfa/webauthn/begin` then `…/finish` — the WebAuthn assertion ceremony

Only that second request returns the JWT and sets the session cookies.
Challenges are single-use and expire after five minutes, and TOTP time
steps are burned on use, so a code cannot be replayed inside its window.
Both steps sit behind the same per-IP login rate limit.

### Enrollment

Users enroll from their profile page: **Two-factor authentication** →
*Set up* for an authenticator app, or *Register* for a passkey or security
key. Removing a factor, or regenerating recovery codes, requires
re-entering the account password so a hijacked session cannot strip
protection off an account.

Recovery codes are shown once, at enrollment. Regenerating them
invalidates the previous set.

### Requiring it

| Setting | Flag | Environment variable |
| --- | --- | --- |
| `service.mfaRequired` | `--mfa-required` | `SERVICE_MFA_REQUIRED` |
| `service.mfaIssuer` | `--mfa-issuer` | `SERVICE_MFA_ISSUER` |
| `service.mfaRPID` | `--mfa-rpid` | `SERVICE_MFA_RPID` |
| `service.mfaOrigins` | `--mfa-origins` | `SERVICE_MFA_ORIGINS` |

With `mfaRequired` on, a user who has no factor is not locked out: the
login returns an enrollment challenge, they scan a QR code and confirm a
code, and the session is issued together with their recovery codes. The
last remaining factor on an account cannot be removed while this is on.

### WebAuthn configuration

Passkeys and security keys need a Relying Party ID and the exact origins
the SPA is served from. `mfaRPID` defaults to `service.host` and
`mfaOrigins` to `https://<rp id>`, which is right for a deployment served
at its own hostname over TLS. Set them explicitly when the SPA is served
on a non-default port or under a different hostname:

```yaml
service:
  host: osctrl.example.com
  mfaRequired: true
  mfaRPID: osctrl.example.com
  mfaOrigins: "https://osctrl.example.com,https://osctrl.example.com:8443"
```

If neither can be resolved, WebAuthn stays off — TOTP and recovery codes
keep working and the SPA hides passkey registration. Browsers also refuse
WebAuthn on plain HTTP other than `localhost`, so a non-TLS deployment is
TOTP-only in practice.

Changing `mfaRPID` invalidates every registered credential: the keys are
bound to the domain they were created for. Users have to register again.

### Locked-out users

There is no self-service reset. An administrator with database access
clears the affected user's rows:

```sql
DELETE FROM user_mfa_totp WHERE username = 'someone';
DELETE FROM user_mfa_credentials WHERE username = 'someone';
DELETE FROM user_mfa_recovery_codes WHERE username = 'someone';
```

The next login then goes through enrollment again (or straight through,
if `mfaRequired` is off).

---

## OIDC

### Generic OIDC setup

1. Register a **Regular Web Application** (or "Confidential Client") in your IdP.
2. Set the **grant type** to `authorization_code`.
3. Add the callback URL: `https://<your-osctrl-host>/api/v1/auth/oidc/callback`.
4. Add the allowed logout URL: `https://<your-osctrl-host>/login`.
5. Ensure the id_token includes the claim you configure as `OIDC_USERNAME_CLAIM`.
6. If using group-based access control, ensure the id_token includes a `groups`
   claim (or whatever you set `OIDC_GROUPS_CLAIM` to).

### Keycloak (OIDC)

Keycloak works with default settings after creating a client. Key points:

**Client configuration:**
- Client type: OpenID Connect
- Client authentication: ON (confidential)
- Valid redirect URIs: `https://<host>/api/v1/auth/oidc/callback`
- Valid post logout redirect URIs: `https://<host>/login`

**Username claim:** Keycloak populates `preferred_username` by default,
which is osctrl's default `OIDC_USERNAME_CLAIM`. No extra configuration
needed.

**Groups claim:** Add a "Group Membership" mapper to the client:
- Mapper type: Group Membership
- Token claim name: `groups`
- Full group path: OFF (otherwise you get `/group-name` instead of `group-name`)

**osctrl environment variables:**
```
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://keycloak.example.com/realms/your-realm
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=<client-secret>
OIDC_REDIRECT_URL=https://<osctrl-host>/api/v1/auth/oidc/callback
OIDC_JIT_PROVISION=true
OIDC_USE_PKCE=true
```

### Auth0 (OIDC)

Auth0 requires two non-default changes that will cause silent failures if
missed.

**1. Switch id_token signing to RS256** (critical)

Auth0 defaults new "Regular Web Application" clients to **HS256** (symmetric
signing). osctrl's OIDC library (`go-oidc`) validates tokens using the IdP's
JWKS (public keys) and rejects HS256 tokens.

**Symptom if missed:** OIDC callback silently fails; the API log shows
`oidc: id_token verification failed`.

**Fix:** Applications > your app > Settings > Advanced Settings > OAuth tab >
JsonWebToken Signature Algorithm > select **RS256** > Save.

**2. Set `OIDC_USERNAME_CLAIM=nickname`**

Auth0's default `sub` claim looks like `auth0|6a0a4280...` which contains
`|` and fails osctrl's username validation. Auth0 populates the `nickname`
claim by default from the user's username (the part before `@`).

**Symptom if missed:** OIDC login succeeds at Auth0 but the user sees a
redirect back to `/` with no session. The API log shows
`oidc: username failed character validation`.

**3. Groups claim requires an Auth0 Action**

Auth0 does not include group/role information in id_tokens by default.
If you want group-based access control, create a post-login Action:

Actions > Flows > Login > Add Action > Build from Scratch:
```javascript
exports.onExecutePostLogin = async (event, api) => {
  const groups = (event.authorization?.roles) || [];
  api.idToken.setCustomClaim('groups', groups);
};
```

Deploy the Action and add it to the Login flow.

**4. Allowed callback and logout URLs**

Applications > your app > Settings:
- Allowed Callback URLs: `https://<osctrl-host>/api/v1/auth/oidc/callback`
- Allowed Logout URLs: `https://<osctrl-host>/login`

**osctrl environment variables:**
```
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://<tenant>.auth0.com/
OIDC_CLIENT_ID=<client-id>
OIDC_CLIENT_SECRET=<client-secret>
OIDC_REDIRECT_URL=https://<osctrl-host>/api/v1/auth/oidc/callback
OIDC_USERNAME_CLAIM=nickname
OIDC_JIT_PROVISION=true
OIDC_USE_PKCE=true
```

### Okta (OIDC)

**Username claim:** Okta commonly populates `preferred_username` with the
user's email address. Valid email usernames are supported and stored
lowercased. Use a short identifier claim only when that better matches your
existing osctrl account names.

**Logout requirement:** Okta REQUIRES `id_token_hint` when chaining a
`post_logout_redirect_uri`. osctrl handles this automatically — the
logout endpoint returns the `id_token_hint` from the session and the
SPA includes it in the IdP logout URL.

### Entra ID (OIDC)

**Username claim:** Entra ID commonly uses an email-shaped
`preferred_username` or `upn`. Valid email usernames are
supported and stored lowercased. Select a custom claim only when you need to
match pre-existing short account names.

**Groups claim:** Entra ID can emit groups as object IDs or display
names. Configure: Enterprise Applications > your app > Token Configuration >
Add groups claim > select "Security groups" > emit as "sAMAccountName"
(or display name) rather than object IDs.

---

## SAML 2.0

### Generic SAML setup

1. Register osctrl as a Service Provider (SP) in your IdP.
2. Point the IdP at the SP metadata URL:
   `https://<osctrl-host>/api/v1/auth/saml/metadata`
   (or download the XML from that URL and upload it to the IdP).
3. Configure the IdP to include a username attribute in the assertion.
4. Set `SAML_USERNAME_ATTRIBUTE` to the exact attribute name the IdP sends.

**SP signing (recommended):** Generate a certificate/key pair and
configure `SAML_SIGNING_CERT` and `SAML_SIGNING_KEY`. This causes osctrl
to sign every AuthnRequest, which some IdPs require and all should
support.

```bash
openssl req -x509 -newkey rsa:2048 -keyout saml-sp.key -out saml-sp.crt \
  -days 3650 -nodes -subj "/CN=osctrl-saml-sp"
```

### Keycloak (SAML)

**Client configuration:**
- Client type: SAML
- Client ID: the `SAML_ENTITY_ID` value (typically the metadata URL)
- Root URL: `https://<osctrl-host>`
- Valid redirect URIs: `https://<osctrl-host>/api/v1/auth/saml/acs`
- Master SAML Processing URL: `https://<osctrl-host>/api/v1/auth/saml/acs`

**Username attribute:** Keycloak sends `preferred_username` in a standard
SAML attribute by default. Set:
```
SAML_USERNAME_ATTRIBUTE=preferred_username
```

Or add a "User Attribute" mapper to send a custom attribute.

**SP signing:** If providing a signing cert, upload `saml-sp.crt` to the
client's Keys tab > Client Signature Required: ON > import the cert.

**osctrl environment variables:**
```
SAML_ENABLED=true
SAML_IDP_METADATA_URL=https://keycloak.example.com/realms/your-realm/protocol/saml/descriptor
SAML_ENTITY_ID=https://<osctrl-host>/api/v1/auth/saml/metadata
SAML_ACS_URL=https://<osctrl-host>/api/v1/auth/saml/acs
SAML_USERNAME_ATTRIBUTE=preferred_username
SAML_JIT_PROVISION=true
SAML_SIGNING_CERT=/path/to/saml-sp.crt
SAML_SIGNING_KEY=/path/to/saml-sp.key
```

### Auth0 (SAML)

Auth0 SAML has two significant gotchas compared to Keycloak.

**1. Attribute namespace differs from the standard**

Auth0 publishes SAML attributes under `http://schemas.auth0.com/` instead
of the standard `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/`
namespace. You must use the Auth0 URI as the attribute name.

**Symptom if missed:** SAML login completes at Auth0 but the user sees a
redirect back to `/` with no session. The API log shows
`saml: username failed character validation` or the NameID is an email
address that fails the username regex.

**Common Auth0 SAML attributes:**
| Auth0 attribute | Value |
|-----------------|-------|
| `http://schemas.auth0.com/nickname` | `alice` |
| `http://schemas.auth0.com/email` | `alice@example.com` |
| `http://schemas.auth0.com/name` | `Alice Smith` |
| `http://schemas.auth0.com/identities/default/connection` | `Username-Password-Authentication` |

**Recommended setting:**
```
SAML_USERNAME_ATTRIBUTE=http://schemas.auth0.com/nickname
```

**2. Enable the SAML2 Web App addon**

Applications > your app > Addons > SAML2 Web App > toggle ON.

Configure:
- Application Callback URL: `https://<osctrl-host>/api/v1/auth/saml/acs`
- Settings (JSON): leave defaults unless you need to customize attribute
  mappings

The metadata URL is:
`https://<tenant>.auth0.com/samlp/metadata/<client-id>`

**3. Logout URL**

Auth0's generic `/v2/logout` endpoint terminates the IdP session regardless
of which protocol (OIDC or SAML) created it. Set `SAML_LOGOUT_URL` so
the SPA can navigate there on logout:

```
SAML_LOGOUT_URL=https://<tenant>.auth0.com/v2/logout
```

Also add the osctrl login page to Auth0's allowed logout URLs:
Applications > your app > Settings > Allowed Logout URLs:
`https://<osctrl-host>/login`

**osctrl environment variables:**
```
SAML_ENABLED=true
SAML_IDP_METADATA_URL=https://<tenant>.auth0.com/samlp/metadata/<client-id>
SAML_ENTITY_ID=https://<osctrl-host>/api/v1/auth/saml/metadata
SAML_ACS_URL=https://<osctrl-host>/api/v1/auth/saml/acs
SAML_USERNAME_ATTRIBUTE=http://schemas.auth0.com/nickname
SAML_JIT_PROVISION=true
SAML_LOGOUT_URL=https://<tenant>.auth0.com/v2/logout
SAML_SIGNING_CERT=/path/to/saml-sp.crt
SAML_SIGNING_KEY=/path/to/saml-sp.key
```

---

## Logout and IdP session termination

osctrl implements a two-step logout:

1. **Server-side:** `POST /api/v1/logout` clears the session cookies and
   revokes the JWT in the database.
2. **IdP-side:** The SPA navigates to the IdP's logout endpoint to
   terminate the IdP session. Without this, the next SSO login silently
   re-authenticates against the still-valid IdP session cookie.

**OIDC logout** uses the standard RP-Initiated Logout flow
(`end_session_endpoint` from the IdP's discovery document). osctrl
discovers this URL automatically. The SPA passes `post_logout_redirect_uri`,
`id_token_hint`, and `client_id` as query parameters.

**SAML logout** does not use SAML SLO (Single Logout) in v1. Instead,
when `SAML_LOGOUT_URL` is configured, the SPA navigates to the IdP's
generic session termination endpoint (e.g. Auth0's `/v2/logout`) with
`returnTo` and `client_id` parameters. This terminates the IdP session
the same way OIDC logout does.

If `SAML_LOGOUT_URL` is not set, SAML users are logged out of osctrl
only. The IdP session remains active, which means the next SSO login
will silently re-authenticate. To mitigate this without setting a logout
URL, set `SAML_FORCE_AUTHN=true` (the default) — this forces the IdP
to prompt for credentials on every login even when an IdP session exists.

---

## Running OIDC and SAML simultaneously

osctrl supports enabling both OIDC and SAML at the same time. The login
page shows separate buttons for each: "Continue with SSO (OIDC)" and
"Continue with SSO (SAML)". Both can point to the same IdP (e.g. Auth0
or Keycloak) or to different IdPs.

When both are enabled against the same IdP, use the same `OIDC_CLIENT_ID`
for both protocols. This ensures the `client_id` parameter on logout
URLs works correctly for both flows.

Users who were originally provisioned via OIDC can later log in via SAML
(or vice versa) as long as the resolved username matches. The session's
authentication method is tracked per-login, not per-user — logout
terminates the correct IdP session regardless of which method was used
to create the osctrl user account.

---

## Troubleshooting

### OIDC login redirects back to `/` with no session

Check the osctrl-api logs for one of:
- `oidc: id_token verification failed` — the id_token signing algorithm
  is likely HS256; switch to RS256 in the IdP.
- `oidc: username failed character validation` — the configured claim is
  neither a valid short handle nor a valid email address. Select a supported
  claim such as `preferred_username`, verified `email`, or `nickname`.
- `oidc: state mismatch` — the state cookie expired (10-minute TTL) or
  the callback URL doesn't match `OIDC_REDIRECT_URL`.

### SAML login redirects back to `/` with no session

Check the osctrl-api logs for one of:
- `saml: assertion validation failed` — signature verification,
  audience, or time window check failed. Verify that the IdP metadata
  URL is correct and that the `SAML_ENTITY_ID` matches the IdP's
  expected audience.
- `saml: username failed character validation` — the username attribute is
  neither a valid short handle nor a valid email address. Make sure
  `SAML_USERNAME_ATTRIBUTE` points to an appropriate identity value (see
  [Username rules](#username-rules)).
- `saml: state cookie missing or invalid` — the state cookie expired or
  the ACS URL doesn't match `SAML_ACS_URL`.

### Logout doesn't kill the IdP session

- **OIDC:** Verify the IdP's discovery document includes
  `end_session_endpoint`. Check that `https://<osctrl-host>/login` is
  in the IdP's allowed logout/redirect URLs.
- **SAML:** Set `SAML_LOGOUT_URL` to the IdP's session termination
  endpoint and add `https://<osctrl-host>/login` to the IdP's allowed
  logout URLs.

### "user not found" after successful IdP login

JIT provisioning is disabled by default. Set `OIDC_JIT_PROVISION=true`
and/or `SAML_JIT_PROVISION=true` to auto-create users on first login.
JIT-provisioned users are created as non-admin; an existing admin must
grant elevated permissions.

### Groups gate blocks login

If `OIDC_REQUIRED_GROUPS` is set, the user must belong to at least one of
the listed groups. Verify:
- The IdP includes the groups claim/attribute in the token/assertion.
- The group name matches exactly (case-sensitive).
- For Auth0: a post-login Action is required to inject the `groups`
  claim (see [Auth0 OIDC](#auth0-oidc)).
- For Keycloak: a "Group Membership" mapper is configured on the client
  with "Full group path" OFF.
