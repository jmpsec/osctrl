# Device risk evidence

Posture scores describe observed device configuration risk. They are not a SOC 2
attestation, an ISO 27001 certification, or a percentage of compliance. The control
mappings below are osctrl's interpretation of relevant objectives from the
[AICPA Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
and [ISO/IEC 27001:2022](https://www.iso.org/standard/27001).
Applicability, exceptions and audit conclusions belong to the organization's
risk assessment and control owners.

## Additional technical checks

These checks supplement encryption, account, inventory, network exposure and
other existing rules. Each rule contributes once, even when it has multiple
evidence sources or appears in multiple profiles. The primary mapping is returned
in the existing control result; the related objective is documented here without
scoring the same evidence twice.

| Check | osquery tables / scope | Primary mapping; related objective | Baseline and limitations |
| --- | --- | --- | --- |
| Secure Boot | `secureboot`; all profiles | ISO A.8.9; SOC 2 CC7.1 | Explicitly enabled. Unsupported firmware or unreadable state warns. This does not assess every boot-policy option. |
| macOS firewall | `alf`; macOS | SOC 2 CC6.6; ISO A.8.20 | `global_state` 1 or 2; 0 fails. Exceptions are not assessed. |
| Gatekeeper | `gatekeeper`; macOS | SOC 2 CC6.8; ISO A.8.7 | Application assessments enabled. This is execution protection, not proof of complete malware protection. |
| System Integrity Protection | `sip_config`; macOS | ISO A.8.9; SOC 2 CC7.1 | Overall `sip` flag enabled. Individual `allow_*` flags have different semantics and are excluded. |
| Screen lock | `screenlock`; macOS | ISO A.8.1; SOC 2 CC6.1 | Password required on wake with at most 60 seconds grace. The 60-second value is an osctrl baseline, not a framework mandate. The table covers only osquery's current logged-in user context; it does not establish idle timeout or all-user coverage. |
| Windows firewall | `windows_security_center`; Windows laptops | SOC 2 CC6.6; ISO A.8.20 | Firewall health `Good`; `Poor` or `Snoozed` fails. |
| Windows antivirus | `windows_security_center`; Windows laptops | SOC 2 CC6.8; ISO A.8.7 | Antivirus health `Good`; `Poor` or `Snoozed` fails. Third-party product health depends on registration with Security Center. |
| Windows automatic updates | `windows_security_center`; Windows laptops | SOC 2 CC7.1; ISO A.8.8 | Automatic update health `Good`. Does not prove patches are current. |
| User Account Control | `windows_security_center`; Windows laptops | ISO A.8.2; SOC 2 CC6.1 | Elevation-control health `Good`. Does not inventory administrator rights. |
| Reversible password storage | `security_profile_info`; Windows | ISO A.5.17; SOC 2 CC6.1 | `clear_text_password` must be 0. Assesses local policy only. |
| Mandatory access controls | `selinux_settings`, `apparmor_profiles`; Linux | ISO A.8.3; SOC 2 CC6.1 | Enforcing SELinux or nonempty, entirely enforcing AppArmor profiles. Empty alternative providers are allowed. Missing/non-enforcing evidence warns; actual policy coverage still needs review. |
| Address space randomization | `system_controls`; Linux | ISO A.8.9; SOC 2 CC7.1 | `kernel.randomize_va_space` must be 2; 0 or 1 fails this baseline. |
| Audit service availability | `systemd_units` (`auditd.service`); Linux. `services` (`EventLog`); Windows | SOC 2 CC7.2; ISO A.8.15 | Running/active service. Stopped/failed/inactive fails; absent or transitional state warns. Non-systemd Linux requires alternate collection. Audit rules, event completeness, forwarding and retention are not assessed. |

The queries use columns in the bundled `deploy/osquery/data/5.23.1.json` schema.
Tests prepare the new SQL against that schema and check platform applicability.
Actual table availability still depends on osquery version, OS, permissions and
runtime configuration. Relevant upstream details:

- [osquery table specifications](https://github.com/osquery/osquery/tree/master/specs)
- [SIP flag implementation](https://github.com/osquery/osquery/blob/master/osquery/tables/system/darwin/sip_config.cpp)
- [Windows Security Center health semantics](https://github.com/osquery/osquery/blob/master/osquery/tables/system/windows/windows_security_center.cpp)
- [Microsoft Security Center API support](https://learn.microsoft.com/en-us/windows/win32/api/wscapi/nf-wscapi-wscgetsecurityproviderhealth): Windows Server is unsupported, so Security Center checks are excluded from the server profile.

## Scoring and evidence quality

Lower scores mean less observed risk. Existing weights remain critical=30,
high=20, medium=10 and low=5, with administrator overrides supported. A pass earns
zero points, a failure earns the rule's weight, and a warning earns one quarter
of its weight (integer division). The aggregate is earned points divided by
possible points for evaluated rules, rounded to 0–100. A failed high-severity
check raises the risk level to at least high; a failed critical check raises it
to critical regardless of other passing checks.

New checks recognize explicit secure and insecure states. Empty results,
missing fields, unsupported states, `Error` and `Not Monitored` warn rather than
pass. A confirmed failure is retained even when other evidence is incomplete.
Scoring uses the full stored snapshot when it contains more rows than the
100-row summary. Invalid or truncated evidence cannot produce a pass; if the
256 KiB snapshot cap prevents full evaluation, the available evidence can still
produce a failure or a warning.

Uncollected categories remain unevaluated to preserve existing platform and
custom-schedule behavior. There is no freshness penalty, expected-control
coverage calculation or vulnerability-feed correlation. Consequently, a low
score does not establish complete or current coverage. Review `last_seen` and
the applied schedule alongside the score. Package/hotfix inventory, arbitrary
process counts and uptime alone do not prove patch compliance or compromise.

## Rollout

1. Upgrade the API and TLS services with posture enabled. Startup adds missing
   checks without overwriting administrator changes; no model change is needed.
2. Review the appropriate posture profile and apply it to each environment's
   schedule through the existing environment configuration workflow or CLI.
   Existing saved schedules are not changed automatically. Review the merge if
   an existing scheduled query was customized.
3. Wait for the new daily snapshot queries, or choose a shorter supported
   interval when applying the profile. Both device-detail and fleet risk
   summaries then use the new evidence. During a mixed-version rollout, older
   services cannot evaluate the new rules consistently.

Disabling a check excludes its evidence from scoring and from generated
profiles. Reseeding preserves the disabled state. Removal of an already deployed
query still requires updating the environment schedule. Per-check UI exclusions
remain a local what-if calculation, not a persisted exception.
