# Configuring Identity Providers for osctrl

osctrl-api supports three authentication methods simultaneously: local
password, OIDC, and SAML 2.0. This guide covers IdP-side configuration
for the two federated protocols and documents the non-obvious gotchas
for each tested provider.

## Table of contents

- [Environment variables reference](#environment-variables-reference)
- [Username rules](#username-rules)
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

## Environment variables reference

### OIDC

| Variable | Required | Description |
|----------|----------|-------------|
| `OIDC_ENABLED` | yes | Set `true` to enable the OIDC login surface |
| `OIDC_ISSUER_URL` | yes | Issuer URL (realm root); `/.well-known/openid-configuration` is appended automatically |
| `OIDC_CLIENT_ID` | yes | Client ID registered with the IdP |
| `OIDC_CLIENT_SECRET` | yes | Client secret |
| `OIDC_REDIRECT_URL` | yes | Must match the IdP's allowed callback and end with `/api/v1/auth/oidc/callback` |
| `OIDC_SCOPES` | no | Comma-separated list (default: `openid,profile,email`) |
| `OIDC_USERNAME_CLAIM` | no | id_token claim to use as the osctrl username (default: `preferred_username`; see [Username rules](#username-rules)) |
| `OIDC_GROUPS_CLAIM` | no | id_token claim containing group memberships (default: `groups`) |
| `OIDC_REQUIRED_GROUPS` | no | Comma-separated group names; login is denied unless the user belongs to at least one |
| `OIDC_JIT_PROVISION` | no | Set `true` to auto-create osctrl users on first login (as non-admin) |
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
| `SAML_FORCE_AUTHN` | no | Force re-authentication at the IdP on every login (default: `true`) |
| `SAML_SIGNING_CERT` | no | Path to PEM certificate for signing AuthnRequests |
| `SAML_SIGNING_KEY` | no | Path to PEM RSA private key for signing AuthnRequests |
| `SAML_LOGOUT_URL` | no | IdP session-termination URL; returned to the SPA so it can end the IdP session on logout |

---

## Username rules

osctrl enforces a strict character set for usernames: `^[a-zA-Z0-9_-]{1,64}$`.
Any value from the IdP that contains characters outside this set (dots,
`@`, `|`, spaces) is rejected. This affects which claim/attribute you
configure:

| IdP claim/attribute | Typical value | Passes? |
|---------------------|---------------|---------|
| `preferred_username` | `alice` | yes |
| `nickname` | `alice` | yes |
| `email` | `alice@example.com` | **no** — contains `@` and `.` |
| `sub` (Auth0) | `auth0\|6a0a...` | **no** — contains `\|` |
| `sub` (Keycloak) | `a1b2c3d4-...` | **no** — contains `-` longer than 64 chars (UUID is 36) |
| NameID (email format) | `alice@example.com` | **no** |

**Recommendation:** always set `OIDC_USERNAME_CLAIM=nickname` (or
`preferred_username` if your IdP populates it) and
`SAML_USERNAME_ATTRIBUTE` to an attribute that carries a short
alphanumeric identifier.

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

**Username claim:** Okta populates `preferred_username` with the user's
login (email format by default). If the login is an email address, set
`OIDC_USERNAME_CLAIM` to a claim that carries a short identifier, or
configure Okta to use a non-email login format.

**Logout requirement:** Okta REQUIRES `id_token_hint` when chaining a
`post_logout_redirect_uri`. osctrl handles this automatically — the
logout endpoint returns the `id_token_hint` from the session and the
SPA includes it in the IdP logout URL.

### Entra ID (OIDC)

**Username claim:** Entra ID uses `upn` (User Principal Name) which is
typically an email address and fails username validation. Set
`OIDC_USERNAME_CLAIM` to a custom claim or to `preferred_username` if
you have configured it in your token configuration.

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
- `oidc: username failed character validation` — the configured
  username claim contains characters outside `[a-zA-Z0-9_-]`. Set
  `OIDC_USERNAME_CLAIM` to a claim with a clean value (e.g. `nickname`).
- `oidc: state mismatch` — the state cookie expired (10-minute TTL) or
  the callback URL doesn't match `OIDC_REDIRECT_URL`.

### SAML login redirects back to `/` with no session

Check the osctrl-api logs for one of:
- `saml: assertion validation failed` — signature verification,
  audience, or time window check failed. Verify that the IdP metadata
  URL is correct and that the `SAML_ENTITY_ID` matches the IdP's
  expected audience.
- `saml: username failed character validation` — the username attribute
  value contains invalid characters. Make sure `SAML_USERNAME_ATTRIBUTE`
  points to an attribute with a clean short identifier (see
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

If `OIDC_REQUIRED_GROUPS` or the SAML equivalent is set, the user must
belong to at least one of the listed groups. Verify:
- The IdP includes the groups claim/attribute in the token/assertion.
- The group name matches exactly (case-sensitive).
- For Auth0: a post-login Action is required to inject the `groups`
  claim (see [Auth0 OIDC](#auth0-oidc)).
- For Keycloak: a "Group Membership" mapper is configured on the client
  with "Full group path" OFF.
