# Security Policy

## Reporting a Vulnerability

The `osctrl` project takes security vulnerabilities seriously.

If you believe you have found a security issue in `osctrl`, **please do not open a public GitHub issue**.

Instead, report it responsibly by emailing:

📧 <osctrl-security@jmpsec.com>

Please include:

- A clear description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected versions or components
- Potential impact (e.g., RCE, privilege escalation, data exposure)
- Any suggested mitigation or fix (if available)

We will acknowledge receipt of your report as soon as possible and work with you to assess and remediate the issue.

---

## Supported Versions

Security fixes are provided for the **latest released version** of `osctrl`.

Users are strongly encouraged to keep their deployments up to date and follow release notes closely, especially for **breaking changes** and security-related updates.

---

## Disclosure Policy

We follow a **responsible disclosure** process:

- Reporters will receive confirmation of the vulnerability report.
- We will investigate and validate the issue.
- We will work on a fix and coordinate a release.
- Public disclosure will occur **after a fix is available**, or in coordination with the reporter when appropriate.

We appreciate responsible disclosure and will credit reporters when possible (unless anonymity is requested).

---

## Security Considerations

`osctrl` is a security-sensitive system that manages endpoint telemetry and remote query execution. Operators should take care to:

- Secure API endpoints and credentials
- Use TLS and strong authentication mechanisms
- Restrict access to administrative interfaces
- Monitor logs and audit trails
- Apply upgrades promptly, especially for security-related releases

---

## Third-Party Dependencies

`osctrl` relies on third-party open source components. Dependency updates and security fixes are regularly tracked and applied.

If a vulnerability is discovered in a third-party dependency that affects `osctrl`, it should be reported following the same process above.

---

## Acknowledgements

We thank the security community for helping keep `osctrl` and its users safe.
