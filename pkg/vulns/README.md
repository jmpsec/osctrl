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
- packages in an ecosystem whose OSV feed hasn't synced yet;
- versions without a digit.

## Severity

- **Source:** CVSS v3 (else v4) vectors published in the OSV record, scored
  locally.
- **No vector:** many Debian and Ubuntu records publish none, and their
  severity is `unknown`.
- **KEV:** a finding is flagged when any CVE alias of its advisory is in the
  CISA catalog.

## Alerts

A `vuln_finding` alert rule fires when a node gains an open confirmed finding at
or above the rule's threshold:

| Threshold | Matches |
| --- | --- |
| `kev` | Known-exploited findings only |
| `critical` | Critical findings, plus all known-exploited |
| `high` | High and critical, plus all known-exploited |
| `medium` | Medium, high and critical, plus all known-exploited |
| `low` | Low and above, plus all known-exploited |
| `any` | Everything, including unknown severity |

How it fires:

- **Where:** the watcher runs in osctrl-tls, so it needs `--alerts-enabled` and
  `--vuln-enabled` there. The API refuses `vuln_finding` rules when vulnerability
  monitoring is off.
- **Grouping:** findings are grouped per advisory, so one advisory affecting
  many nodes is one notification.
- **Cap:** each rule sends at most 10 advisories per environment per hour,
  worst first within a sweep, plus one digest per hour for the rest. The budget
  lives in Redis, so it holds across sweeps and osctrl-tls replicas; an
  inventory rollout or a fleet-wide re-match can't page once a minute.
- **Once only:** a finding alerts when it first appears, including on a node's
  first inventory. A reopened finding doesn't alert again.
- **Not re-alerted:** a finding that later becomes known-exploited (added to
  CISA KEV) or rises in severity does not alert again. A `kev` rule fires only
  for findings that are already KEV when recorded.
- **Restarts:** a Redis cursor (`osctrl:alert:vuln:cursor`) prevents re-alerting.
  Deleting the cursor restarts from the newest finding; it never replays history.
- **Possible findings:** never alert.

## Posture score

With `--posture-enabled` and `--vuln-enabled` on osctrl-api, nodes get a
"Known vulnerabilities" control (ISO 27001 A.8.8):

| Open confirmed findings | Result |
| --- | --- |
| Any KEV or critical | Fail at critical weight; risk level critical |
| Otherwise any high | Fail at high weight |
| Otherwise any medium, low or unknown | Warn |
| None | Pass |

The control is unevaluated, never passed, before advisory data has loaded and
for a node without findings that has never been matched or has no assessed
packages (Amazon Linux, an OS-only Windows node, an ecosystem whose feed hasn't
synced). A node with no findings but some packages not assessed warns: not
assessed is never clean.

## Health

The health page shows an "Advisory feeds" component:

- **degraded** when a feed's last error is newer than its last success;
- **unknown** before the first OSV sync;
- **stale** after three missed sync intervals.

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
