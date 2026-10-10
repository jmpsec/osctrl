# Vulnerability monitoring

Off by default. `--vuln-enabled` on osctrl-tls stores software inventory;
on osctrl-api it downloads advisory data, matches it and serves findings.
Package inventory never leaves the deployment: the only outbound traffic is
the feed downloads below, to URLs the operator controls.

## Data flow

1. Apply a `vuln-linux`, `vuln-darwin` or `vuln-windows` profile
   (`GET /api/v1/vulnerabilities/profiles`) to an environment's schedule.
   The queries run daily in snapshot mode.
2. osctrl-tls replaces each node's `node_software` rows per category on every
   snapshot and records the OS in `vuln_node_state`.
3. One osctrl-api replica (SQL lease) syncs the OSV ecosystems the fleet
   reports, plus the CISA KEV catalog, every `--vuln-sync-hours`. It then
   re-matches nodes whose inventory or advisories changed.

## Coverage

| Inventory | Matched against |
| --- | --- |
| Debian, Ubuntu (incl. non-LTS) `deb_packages` | OSV `Debian:<major>`, `Ubuntu:<release>[:LTS]`, by source package |
| RHEL, Rocky, AlmaLinux `rpm_packages` | OSV `Red Hat:enterprise_linux:<major>::*`, `Rocky Linux:<major>`, `AlmaLinux:<major>` |
| `python_packages` | OSV `PyPI` (PEP 503 names) |
| `npm_packages` (global) | OSV `npm` |

Not assessed, and counted as such rather than reported clean:

- Alpine (osquery has no `apk_packages` table);
- CentOS, SUSE and other distributions;
- Ubuntu Pro/FIPS and RHEL EUS streams;
- Windows and macOS applications (NVD/CPE matching is planned);
- versions without a digit.

## Severity

- **Source:** CVSS v3 (else v4) vectors published in the OSV record, scored
  locally.
- **No vector:** many Debian and Ubuntu records publish none, and their
  severity is `unknown`.
- **KEV:** a finding is flagged when any CVE alias of its advisory is in the
  CISA catalog.

## Air-gapped deployments

Mirror the OSV bucket layout (`<ecosystem>/all.zip`,
`<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and the KEV JSON on
an internal web server. Then set `--vuln-osv-url` and `--vuln-kev-url`. Only
`http` and `https` URLs are accepted.

## Operations

- **Downloads** are capped by `--vuln-max-download-mb`. Archives are read in
  memory and never extracted.
- **Failed syncs** keep existing data and retry after 15 minutes. The API
  reports feeds as `stale` after three missed intervals and `loaded=false`
  before the first OSV sync.
- **Resolved findings** are kept for `--vuln-retention-days`.
- **Deleted nodes:** rows of deleted nodes are swept hourly.
- **Log sinks:** inventory results also flow to the configured log sinks,
  like any scheduled query.
