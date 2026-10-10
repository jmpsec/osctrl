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
   reports, plus the CISA KEV catalog and, with `--vuln-nvd-enabled`, NVD CVEs, every `--vuln-sync-hours`. It then
   re-matches nodes whose inventory or advisories changed.

## Coverage

| Inventory | Matched against |
| --- | --- |
| Debian, Ubuntu (incl. non-LTS) `deb_packages` | OSV `Debian:<major>`, `Ubuntu:<release>[:LTS]`, by source package |
| RHEL, Rocky, AlmaLinux `rpm_packages` | OSV `Red Hat:enterprise_linux:<major>::*`, `Rocky Linux:<major>`, `AlmaLinux:<major>` |
| `python_packages` | OSV `PyPI` (PEP 503 names) |
| `npm_packages` (global) | OSV `npm` |
| Windows `programs`, `chocolatey_packages`; macOS `apps`, `homebrew_packages` | NVD CPE (`--vuln-nvd-enabled`), as **possible** findings |

Not assessed, and counted as such rather than reported clean:

- Alpine (osquery has no `apk_packages` table);
- CentOS, SUSE and other distributions;
- Ubuntu Pro/FIPS and RHEL EUS streams;
- Windows programs, macOS apps, Homebrew and Chocolatey packages while
  `--vuln-nvd-enabled` is off;
- packages in an ecosystem whose OSV feed hasn't synced yet;
- versions without a digit.

## Severity

- **Source:** CVSS v3 (else v4) vectors published in the OSV record, scored
  locally.
- **No vector:** many Debian and Ubuntu records publish none, and their
  severity is `unknown`.
- **KEV:** a finding is flagged when any CVE alias of its advisory is in the
  CISA catalog.

## NVD possible findings

With `--vuln-nvd-enabled`, osctrl-api also syncs CVEs from the NVD CVE API
2.0 and matches Windows programs, macOS apps, Homebrew and Chocolatey
packages by product name.

- **Names:** the installed name and vendor are normalized to CPE spelling.
  The vendor is the Windows publisher or the macOS bundle id. The names are
  then looked up exactly among the products stored CVEs list
  (`vuln_cpe_products`). Without a matching vendor, a product is taken only
  when a single vendor ships it. There is no fuzzy matching.
- **Versions** are compared as dotted numbers. A version without a digit is
  not assessed.
- **Possible, not confirmed:** these findings are shown, de-emphasized, but
  never alert and never count toward the posture score. KEV and severity come
  from the CVE.
- **Severity:** an OSV record without its own CVSS borrows the highest score
  of an aliased NVD CVE; `cvss_from` names the CVE.
- **Application CVEs only** (CPE part `a`) are stored. Kernel and OS CVEs are
  not, so their OSV records keep `unknown` severity unless they carry a CVSS.
- **Rate limits:** requests are paced at NVD's documented limit, one every
  6 seconds without a key; an API key gives ten times the rate. The first
  sync reads about 150 pages of 2,000 CVEs and stores each one, so expect an
  hour or more, during which the worker matches nothing else. Rate-limited
  pages are retried twice; a sync that still fails retries 15 minutes after
  it ended, and a failed first sync resumes from its next page.
- **API key:** set it through `VULN_NVD_API_KEY`; a flag value shows in the
  process list. It is sent only as the `apiKey` header.
- **Turning it off** removes the NVD data on the next worker tick: possible
  findings resolve and borrowed severities revert.

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
- **Escalations:** an open finding that later becomes known-exploited (CISA
  adds its CVE to KEV) or rises in severity alerts again, once, for the rules
  it newly matches: a `kev` rule fires when CISA lists a CVE the fleet already
  has, and a `high` rule when a medium finding becomes high. osctrl-api
  records each escalation in `vuln_escalations` (kept 30 days).
- **Restarts:** Redis cursors (`osctrl:alert:vuln:cursor`,
  `osctrl:alert:vuln:escalation-cursor`) prevent re-alerting. A missing,
  corrupt or expired cursor restarts from the newest record and never replays
  history. Cursors expire after a week without sweeps, so re-enabling alerts
  after a long pause starts from now.
- **Peaks:** an escalation is measured against the highest severity and KEV
  state the finding ever had, so falling and coming back (NVD off for a while,
  a truncated KEV feed) is not news. Escalations recorded before a finding was
  reopened stay silent, and a finding the watcher has not alerted yet alerts
  once with its current state.
- **Replicas:** one osctrl-tls replica sweeps at a time (a Redis lock held for
  the sweep, released when it ends, expiring after 5 minutes if its holder
  dies).
- **Settling:** a sweep takes only findings the previous sweep already
  listed, so one written by a slower match transaction is never skipped.
  Alerts arrive a minute later; no clocks are compared.
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
assessed is never clean. Packages only NVD names cover (Windows programs,
macOS apps, Homebrew, Chocolatey) never count either way, and possible findings
never affect the score.

## Health

The health page shows an "Advisory feeds" component:

- **degraded** when a feed's last error is newer than its last success;
- **unknown** before the first OSV sync;
- **stale** after three missed sync intervals.

## Air-gapped deployments

Mirror the OSV bucket layout (`<ecosystem>/all.zip`,
`<ecosystem>/modified_id.csv`, `<ecosystem>/<id>.json`) and the KEV JSON on
an internal web server. Then set `--vuln-osv-url` and `--vuln-kev-url`. Only
`http` and `https` URLs are accepted. Leave NVD off, or point `--vuln-nvd-url`
at a mirror that serves the API's responses.

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
- **Metrics:** with `--metrics-enabled` and `--vuln-enabled`, osctrl-tls
  exports gauges read from the shared database (cached for a minute):
  `osctrl_vuln_advisories`, `osctrl_vuln_feed_last_success_timestamp_seconds`
  (per source), `osctrl_vuln_findings_open` (per confidence),
  `osctrl_vuln_findings_resolved`, `osctrl_vuln_nodes_pending_match` and
  `osctrl_vuln_packages_not_assessed`. Every osctrl-tls replica exports the
  same fleet-wide values: aggregate with `max()`, not `sum()`. A reading that
  fails or takes over 10 seconds exports nothing.
- **Rejected records:** an advisory the database rejects is skipped and
  counted (`last_skipped`), not retried forever.
- **NVD on some replicas only:** a replica with `--vuln-nvd-enabled` off keeps
  NVD data while another replica used NVD in the last hour, and logs a
  warning; set the flag the same everywhere.
