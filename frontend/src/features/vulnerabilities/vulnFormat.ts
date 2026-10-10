import type { VulnSeverity } from '$/api/vulnerabilities';

/** Most severe first: the order of the filter chips and summary counts. */
export const SEVERITIES: VulnSeverity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

export function severityVariant(severity: VulnSeverity): 'danger' | 'warning' | 'info' | 'dim' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'info';
    default:
      return 'dim';
  }
}

/**
 * Advisory references come from external feeds. Only https URLs become
 * links; javascript:, data:, http: and anything unparseable stay text.
 */
export function safeExternalUrl(raw: string): string | null {
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Server-side caps (pkg/vulns/read.go): the node report returns at most
 * NODE_FINDINGS_LIMIT open findings, and an advisory at most
 * ADVISORY_FINDINGS_LIMIT affected nodes, without a total. A list that
 * reaches its cap says so instead of passing for complete.
 */
export const NODE_FINDINGS_LIMIT = 500;
export const ADVISORY_FINDINGS_LIMIT = 1000;

/** The API serialises an unset Go time.Time as 0001-01-01T00:00:00Z. */
export function hasTime(iso: string | null | undefined): boolean {
  return !!iso && !iso.startsWith('0001-01-01');
}
