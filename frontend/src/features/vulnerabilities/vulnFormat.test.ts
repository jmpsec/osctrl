import { describe, it, expect } from 'vitest';
import { hasTime, safeExternalUrl, severityVariant, SEVERITIES } from './vulnFormat';

describe('safeExternalUrl', () => {
  it.each([
    ['https://example.org/a', 'https://example.org/a'],
    ['HTTPS://Example.org', 'https://example.org/'],
  ])('keeps the https link %s', (input, expected) => {
    expect(safeExternalUrl(input)).toBe(expected);
  });

  // Feed data is external input: anything that is not plain https stays text.
  it.each([
    'javascript:alert(1)',
    ' javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'http://example.org/a',
    '/relative/path',
    '',
    'not a url',
  ])('refuses %j', (input) => {
    expect(safeExternalUrl(input)).toBeNull();
  });
});

describe('severityVariant', () => {
  it('maps every severity to a badge variant, most severe first', () => {
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low', 'unknown']);
    expect(SEVERITIES.map(severityVariant)).toEqual(['danger', 'danger', 'warning', 'info', 'dim']);
  });
});

describe('hasTime', () => {
  it('treats null and Go zero time as absent', () => {
    expect(hasTime(null)).toBe(false);
    expect(hasTime(undefined)).toBe(false);
    expect(hasTime('')).toBe(false);
    expect(hasTime('0001-01-01T00:00:00Z')).toBe(false);
    expect(hasTime('2026-10-10T08:00:00Z')).toBe(true);
  });
});
