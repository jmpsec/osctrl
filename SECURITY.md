# Security Policy

## Reporting a Vulnerability

Do not report suspected vulnerabilities in a public GitHub issue, discussion, or pull request.

Email reports to <osctrl-security@jmpsec.com> and include:

- Affected version, component, and deployment model
- A clear description of the issue and its impact
- Reproduction steps or a proof of concept
- Required privileges or preconditions
- Suggested mitigations, if known

Avoid including live credentials, production data, private keys, or unnecessary personal data. We will acknowledge the report, investigate it, coordinate remediation, and disclose the issue after a fix is available or on an agreed schedule.

## Supported Versions

Security fixes are provided for the latest released version of `osctrl`. Operators should upgrade promptly and review release notes for security and compatibility changes.

## Security Boundaries

`osctrl` manages endpoint telemetry, remote query execution, file collection, and operator credentials. Deployments should:

- Expose `osctrl-tls` and the operator frontend only through correctly configured TLS
- Protect API bearer tokens, JWT signing secrets, enrollment secrets, database credentials, and SAML signing keys
- Keep `osctrl-api` authentication enabled in production
- Restrict administrative and environment permissions to the minimum necessary
- Review audit logs and external log-sink destinations
- Configure retention and backup policies for SQL and Redis data
- Apply operating-system, database, Redis, osquery, and container updates promptly

The `auth=none` API mode requires `OSCTRL_INSECURE_NO_AUTH=1` and is intended only for isolated local development. Hosted MCP is disabled by default, and MCP write tools require a separate explicit opt-in. Neither control should be weakened for production convenience.

Native packages install sample configuration and systemd units but do not start services automatically. Configure deployment-specific secrets before enabling the units.

## Disclosure Process

We aim to:

1. Confirm receipt of the report.
2. Reproduce and assess severity and affected versions.
3. Develop and validate a fix.
4. Coordinate release and disclosure with the reporter.
5. Credit the reporter when requested and appropriate.

Timelines depend on severity, reproducibility, and release complexity. Please allow reasonable time for investigation before public disclosure.

## Third-Party Vulnerabilities

Report dependency vulnerabilities through the same private channel when they affect an `osctrl` deployment. Include the vulnerable dependency, affected code path, and any known exploitability conditions.
