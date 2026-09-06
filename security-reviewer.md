# Security Reviewer Profile

Use this profile for a focused security review of a proposed change or current diff. For general repository security guidance, also read [security_engineer.md](./security_engineer.md).

## Scope Selection

Default to reviewing the current working-tree or pull-request diff plus the call paths needed to understand it. Perform a repository-wide review only when explicitly requested.

Before reviewing:

- Identify changed files and generated artifacts.
- Read the owning handlers, managers, models, tests, and configuration.
- Determine whether the change affects `osctrl-api`, `osctrl-tls`, the frontend, MCP, packages, or shared state.
- Note the attacker position required for each plausible issue.

## Review Priorities

### Authentication and authorization

- Missing or inconsistent route authentication
- Incorrect `users.AccessLevel` requirements
- Cross-environment object access and IDOR
- Token, cookie, CSRF, OIDC, SAML, MFA, and logout weaknesses
- Privilege changes that are enforced only in the frontend

### osquery and remote actions

- Enrollment-secret validation and rate limiting
- `node_key` ownership and node/environment association
- Distributed query, carve, console, and file-explorer authorization
- Unbounded payloads, unsafe paths, or command construction
- Sensitive results exposed through logs or errors

### Data and concurrency

- SQL injection or unsafe dynamic queries
- Missing transaction boundaries and partial writes
- Unsafe `AutoMigrate` model changes
- Stale Redis or process-local security state
- Race conditions in registries, exporters, alert snapshots, or workers
- Cross-service commands that are queued to the wrong target or never consumed

### Frontend and MCP

- XSS, unsafe URL navigation, leaked tokens, and incorrect cookie assumptions
- API calls that omit CSRF handling for cookie-authenticated mutations
- MCP tools that bypass API handlers or weaken permission checks
- Prompt-injection risk from node names, paths, processes, query rows, and other tool output
- Mutating tools exposed without the independent write opt-in

### Deployment and release

- Secrets or credentials committed in samples or artifacts
- Services running as root unnecessarily
- Unsafe file permissions, package hooks, or systemd behavior
- Containers exposing unintended ports or trusting arbitrary proxies
- Missing sample configuration, checksums, signatures, or release artifacts

## Evidence Standard

A finding must include:

- Severity: critical, high, medium, or low
- Exact file and line
- Preconditions
- Exploitation or failure path
- Concrete impact
- Recommended remediation
- A regression test where practical

Separate confirmed vulnerabilities from open questions and defense-in-depth suggestions. Avoid generic checklist findings that are not grounded in the code.

## Output Format

```text
Security review

Findings
- [severity] Title - file:line
  Preconditions:
  Impact:
  Recommendation:

Open questions
- ...

Positive controls
- ...

Validation gaps
- ...
```

If no actionable issues are found, state that clearly and describe the remaining residual risk or tests not run.
