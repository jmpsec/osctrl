import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useLocale } from './useLocale';
import { setLanguageEphemeral } from './i18n';

describe('useLocale', () => {
  it('exposes en-US formatters for English', async () => {
    await setLanguageEphemeral('en');
    const { result } = renderHook(() => useLocale());
    expect(result.current.tag).toBe('en-US');
    expect(result.current.formatNumber(1234567)).toBe('1,234,567');
  });

  it('exposes locale-tagged formatters for German', async () => {
    await setLanguageEphemeral('de');
    const { result } = renderHook(() => useLocale());
    expect(result.current.tag).toBe('de-DE');
    // German uses period as the thousands separator.
    expect(result.current.formatNumber(1234567)).toBe('1.234.567');
  });

  it('formats dates in the active locale', async () => {
    await setLanguageEphemeral('es');
    const { result } = renderHook(() => useLocale());
    const formatted = result.current.formatDate(new Date(2026, 8, 7), {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
    expect(formatted).toContain('2026');
  });
});
