/**
 * Time formatting utilities for the osctrl admin UI.
 */

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

/**
 * Returns a compact relative time string for the given ISO-8601 timestamp.
 *
 * Examples:
 *   3 seconds ago  → "3s"
 *   4 minutes ago  → "4m"
 *   2 hours ago    → "2h"
 *   1 day ago      → "1d"
 *   > 7 days ago   → "Mar 14" (abbreviated month + day)
 *   invalid input  → "—"
 */
export function formatRelative(iso: string): string {
  if (!iso) return '—';

  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';

  const diffMs = Date.now() - d.getTime();

  if (diffMs < 0) {
    // Future timestamp — treat as just now
    return 'just now';
  }

  if (diffMs < MINUTE) {
    const s = Math.floor(diffMs / SECOND);
    return `${s}s`;
  }

  if (diffMs < HOUR) {
    const m = Math.floor(diffMs / MINUTE);
    return `${m}m`;
  }

  if (diffMs < DAY) {
    const h = Math.floor(diffMs / HOUR);
    return `${h}h`;
  }

  if (diffMs < WEEK) {
    const day = Math.floor(diffMs / DAY);
    return `${day}d`;
  }

  // Older than a week — show abbreviated date
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/**
 * Returns a full ISO-8601 timestamp string formatted for display in tooltips.
 * E.g. "2024-03-14 15:09:26 UTC"
 */
export function formatAbsolute(iso: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

/**
 * Returns true if the given ISO timestamp is within the last `hours` hours.
 */
export function isWithinHours(iso: string, hours: number): boolean {
  if (!iso) return false;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return false;
  return Date.now() - d.getTime() < hours * HOUR;
}

/**
 * Compact byte-count formatter for table cells. Uses base-1024 with
 * standard binary unit prefixes (KB / MB / GB / TB), one decimal for sub-100
 * values, zero decimals at or above 100. Returns "—" on falsy/NaN.
 *
 *   0          → "0 B"
 *   512        → "512 B"
 *   2048       → "2.0 KB"
 *   1_234_567  → "1.2 MB"
 *   2_500_000_000 → "2.3 GB"
 */
export function formatBytes(n: number | null | undefined): string {
  if (n == null || isNaN(n)) return '—';
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const formatted = v >= 100 ? Math.round(v).toString() : v.toFixed(1);
  return `${formatted} ${units[i]}`;
}

/**
 * Honest "how long ago" for an event whose time is only known to fall within a
 * fixed-size bucket (e.g. an hourly Redis activity rollup). The timestamp is
 * the bucket START; the event happened somewhere in [bucketStart, bucketEnd).
 *
 * Because the exact instant is unknown, precision is bucket-sized:
 *   - bucket still open (now < bucketEnd) → "within the last hour"
 *   - otherwise → whole hours/days since the bucket started, e.g. "3h ago"
 *
 * Avoids the false minute precision that formatRelative would imply for a
 * bucket-aligned timestamp. Returns "—" for invalid/empty input.
 */
export function formatBucketAgo(iso: string, bucketSeconds = 3600): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const diffMs = Date.now() - d.getTime();
  if (diffMs < 0) return 'just now';
  // bucketSeconds is in seconds; the bucket is still open while now falls
  // within [bucketStart, bucketStart + bucketSeconds).
  if (diffMs < bucketSeconds * 1000) return 'within the last hour';
  const hours = Math.floor(diffMs / HOUR);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
