/**
 * Time formatting utilities for the osctrl admin UI.
 *
 * Compact units and phrasal strings go through i18n so they follow the
 * active language; the long-date fallback uses the locale-tagged Intl
 * formatter (see useLocale). Reads the i18next instance directly so
 * both React components and plain modules (table formatters, chart
 * ticks) get translated output without prop-drilling a `t` function.
 */

import i18next from 'i18next';
import { localeTag, DEFAULT_LANGUAGE } from '$/i18n/locales';

const SECOND = 1_000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

/** Active language, falling back when i18n is not initialized yet. */
function t(key: string, options?: Record<string, unknown>): string {
  return i18next.t(key, options) ?? key;
}

/** Locale-tagged "Mar 14"-style date. */
function shortDate(d: Date): string {
  const language = (i18next.language ?? DEFAULT_LANGUAGE) as Parameters<typeof localeTag>[0];
  return d.toLocaleDateString(localeTag(language), { month: 'short', day: 'numeric' });
}

/**
 * Returns a compact relative time string for the given ISO-8601 timestamp.
 *
 * Examples:
 *   3 seconds ago  → "3s"
 *   4 minutes ago  → "4m"
 *   2 hours ago    → "2h"
 *   1 day ago      → "1d"
 *   > 7 days ago   → "Mar 14" (abbreviated month + day, locale-tagged)
 *   invalid input  → "—"
 */
export function formatRelative(iso: string): string {
  if (!iso) return '—';

  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';

  const diffMs = Date.now() - d.getTime();

  if (diffMs < 0) {
    // Future timestamp — use formatTimeUntil for a proper "in 3d" string.
    return formatTimeUntil(iso);
  }

  if (diffMs < MINUTE) {
    const s = Math.floor(diffMs / SECOND);
    return t('time.secondsShort', { count: s });
  }

  if (diffMs < HOUR) {
    const m = Math.floor(diffMs / MINUTE);
    return t('time.minutesShort', { count: m });
  }

  if (diffMs < DAY) {
    const h = Math.floor(diffMs / HOUR);
    return t('time.hoursShort', { count: h });
  }

  if (diffMs < WEEK) {
    const day = Math.floor(diffMs / DAY);
    return t('time.daysShort', { count: day });
  }

  // Older than a week — show abbreviated date
  return shortDate(d);
}

/**
 * Returns a compact "time until" string for a future ISO-8601 timestamp.
 * Mirrors formatRelative but for future dates.
 *
 * Examples:
 *   in 3 seconds  → "in 3s"
 *   in 4 minutes  → "in 4m"
 *   in 2 hours    → "in 2h"
 *   in 1 day      → "in 1d"
 *   > 7 days      → "Mar 14"
 *   invalid/past  → "—"
 */
export function formatTimeUntil(iso: string): string {
  if (!iso) return '—';

  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';

  const diffMs = d.getTime() - Date.now();
  if (diffMs <= 0) return '—';

  if (diffMs < MINUTE) {
    const s = Math.floor(diffMs / SECOND);
    return t('time.inSeconds', { count: s });
  }
  if (diffMs < HOUR) {
    const m = Math.floor(diffMs / MINUTE);
    return t('time.inMinutes', { count: m });
  }
  if (diffMs < DAY) {
    const h = Math.floor(diffMs / HOUR);
    return t('time.inHours', { count: h });
  }
  if (diffMs < WEEK) {
    const day = Math.floor(diffMs / DAY);
    return t('time.inDays', { count: day });
  }
  return shortDate(d);
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
  if (diffMs < 0) return t('time.justNow');
  // bucketSeconds is in seconds; the bucket is still open while now falls
  // within [bucketStart, bucketStart + bucketSeconds).
  if (diffMs < bucketSeconds * 1000) return t('time.withinLastHour');
  const hours = Math.floor(diffMs / HOUR);
  if (hours < 24) return t('time.hoursAgo', { count: hours });
  const days = Math.floor(hours / 24);
  return t('time.daysAgo', { count: days });
}
