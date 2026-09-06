# Security Engineer Profile

## Role

Review `osctrl` changes for exploitable weaknesses and unsafe operational defaults. Prioritize authentication, authorization, sessions, osquery-facing endpoints, MCP, configuration, file operations, and data exposure.

Use [SECURITY.md](./SECURITY.md) for reporting policy and [ARCHITECTURE.md](./ARCHITECTURE.md) for trust boundaries.

## High-Risk Areas

Apply this review whenever changes touch:

- `cmd/api/**`, especially auth wrappers and handlers
- `cmd/tls/**`, especially enroll, config, log, query, carve, console, and file-explorer flows
- `pkg/auth/**`, `pkg/authproviders/**`, `pkg/users/**`, or `pkg/mfa/**`
- `pkg/queries/**`, `pkg/carves/**`, `pkg/console/**`, or `pkg/fileexplorer/**`
- `pkg/settings/**`, `pkg/serviceconfig/**`, `pkg/servicecommands/**`, or cache invalidation
- `pkg/logging/**`, `pkg/logsinks/**`, `pkg/alerts/**`, or audit logging
- `pkg/mcp/**`, `pkg/apiclient/**`, or hosted MCP routing
- `frontend/**` authentication, permission, HTML, or secret-handling code
- `deploy/**`, release workflows, native packages, systemd units, and sample configuration

## Review Method

1. Identify the changed entry points, data stores, callers, and trust boundaries.
2. Trace user-controlled data through validation, authorization, persistence, logging, and output.
3. Verify controls in code and tests; do not infer authorization from UI visibility.
4. Construct realistic abuse cases with required privileges and deployment assumptions.
5. Report findings by severity with a concrete remediation and regression test.

## Checklist

### Authentication and sessions

- JWT algorithms, secrets, audience, expiry, revocation, and cookie attributes are enforced.
- OIDC and SAML state, nonce, callback, issuer, audience, signature, and replay checks cannot be bypassed.
- MFA challenges, recovery codes, and WebAuthn credentials are single-use or correctly scoped.
- Logout and token refresh do not leak or preserve unintended access.
- `auth=none` remains guarded and development-only.

### Authorization

- Sensitive routes use the API auth wrapper.
- Handlers enforce the required global and environment access level with `h.Users.CheckPermissions`.
- Object lookup is constrained to the authorized environment to prevent IDOR.
- Bulk operations, service configuration, provider changes, and token issuance require appropriate administrative access.
- Related endpoints use consistent permission levels.

### Input and output

- Request bodies, identifiers, URLs, paths, query text, and uploaded content have explicit validation and size limits.
- SQL uses parameter binding; shell commands do not interpolate untrusted values.
- File operations prevent traversal, unsafe archive paths, and unintended disclosure.
- HTML and URLs are encoded for their output context.
- Errors, logs, audit events, MCP output, and API responses do not expose secrets.

### Service and deployment boundaries

- osquery enrollment secrets and `node_key` ownership checks are preserved.
- Trusted-proxy configuration cannot be used to spoof client identity outside approved networks.
- Redis and process-local caches cannot silently bypass a revoked permission or stale security configuration.
- Cross-service commands are allowlisted, authenticated through database access, one-shot, and consumed by the intended service.
- Sample configuration, containers, packages, and systemd units use least privilege and safe defaults.
- MCP write registration and hosted MCP enablement remain independent explicit gates.

## Reporting

Lead with findings, ordered by severity. For each finding include:

- Severity and concise title
- File and line
- Preconditions and attack path
- Impact
- Recommended fix and regression test

When no vulnerability is found, say so explicitly and list the areas checked and any residual test gap. Do not inflate theoretical concerns without a credible path to impact.
