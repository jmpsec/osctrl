import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { formatRelative, formatBucketAgo } from './time';

describe('formatRelative', () => {
  const NOW = new Date('2024-03-14T15:09:26.000Z').getTime();

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns seconds for < 1 minute ago', () => {
    const iso = new Date(NOW - 3_000).toISOString();
    expect(formatRelative(iso)).toBe('3s');
  });

  it('returns minutes for < 1 hour ago', () => {
    const iso = new Date(NOW - 4 * 60_000).toISOString();
    expect(formatRelative(iso)).toBe('4m');
  });

  it('returns hours for < 1 day ago', () => {
    const iso = new Date(NOW - 2 * 3_600_000).toISOString();
    expect(formatRelative(iso)).toBe('2h');
  });

  it('returns days for < 1 week ago', () => {
    const iso = new Date(NOW - 1 * 86_400_000).toISOString();
    expect(formatRelative(iso)).toBe('1d');
  });

  it('returns abbreviated date for > 7 days ago', () => {
    // 2024-03-14 minus 10 days = 2024-03-04
    const iso = new Date(NOW - 10 * 86_400_000).toISOString();
    expect(formatRelative(iso)).toMatch(/^Mar \d+$/);
  });

  it('returns em-dash for empty string', () => {
    expect(formatRelative('')).toBe('—');
  });

  it('returns em-dash for invalid date string', () => {
    expect(formatRelative('not-a-date')).toBe('—');
  });

  it('handles 59 seconds (boundary)', () => {
    const iso = new Date(NOW - 59_000).toISOString();
    expect(formatRelative(iso)).toBe('59s');
  });

  it('handles exactly 60 seconds → 1m', () => {
    const iso = new Date(NOW - 60_000).toISOString();
    expect(formatRelative(iso)).toBe('1m');
  });

  it('handles exactly 1 hour → 1h', () => {
    const iso = new Date(NOW - 3_600_000).toISOString();
    expect(formatRelative(iso)).toBe('1h');
  });

  it('handles exactly 1 day → 1d', () => {
    const iso = new Date(NOW - 86_400_000).toISOString();
    expect(formatRelative(iso)).toBe('1d');
  });
});

describe('formatBucketAgo', () => {
  const NOW = new Date('2024-03-14T15:09:26.000Z').getTime();
  const HOUR = 3_600_000;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns "within the last hour" while the bucket is still open', () => {
    // bucket started 30m ago, has 30m left → event could be just now
    const iso = new Date(NOW - 30 * 60_000).toISOString();
    expect(formatBucketAgo(iso, 3600)).toBe('within the last hour');
  });

  it('returns whole hours once the bucket has closed', () => {
    // bucket started 3h ago (closed) → "3h ago"
    const iso = new Date(NOW - 3 * HOUR).toISOString();
    expect(formatBucketAgo(iso, 3600)).toBe('3h ago');
  });

  it('rolls over to days past 24h', () => {
    const iso = new Date(NOW - 26 * HOUR).toISOString();
    expect(formatBucketAgo(iso, 3600)).toBe('1d ago');
  });

  it('returns "—" for invalid input', () => {
    expect(formatBucketAgo('', 3600)).toBe('—');
    expect(formatBucketAgo('not-a-date', 3600)).toBe('—');
  });
});
