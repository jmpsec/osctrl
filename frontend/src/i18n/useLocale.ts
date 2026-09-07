/**
 * useLocale.ts — locale-aware Intl formatters.
 *
 * The browser's native Intl API does all the formatting work (zero
 * bundle cost); this module just caches formatters per locale so we do
 * not rebuild a DateTimeFormat on every row render. Existing helpers
 * that hardcode "en-US" (lib/time.ts, charts) migrate to these.
 */

import { useMemo } from 'react';
import i18next from 'i18next';
import { useTranslation } from 'react-i18next';
import { localeTag } from './locales';

export interface LocaleFormatters {
  /** Locale tag for Intl / third-party components. */
  tag: string;
  formatDate: (date: Date, options?: Intl.DateTimeFormatOptions) => string;
  formatTime: (date: Date, options?: Intl.DateTimeFormatOptions) => string;
  formatDateTime: (date: Date, options?: Intl.DateTimeFormatOptions) => string;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
}

function buildFormatters(tag: string): LocaleFormatters {
  // Module-level cache keyed by tag: a switch language → switch back
  // cycle reuses the already-constructed Intl objects. Formatter
  // construction is expensive (pattern compilation); formatting itself
  // is cheap.
  const dateCache = new Map<string, Intl.DateTimeFormat>();
  const numberCache = new Map<string, Intl.NumberFormat>();

  function dateTime(options?: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
    const key = JSON.stringify(options ?? null);
    let fmt = dateCache.get(key);
    if (!fmt) {
      fmt = new Intl.DateTimeFormat(tag, options);
      dateCache.set(key, fmt);
    }
    return fmt;
  }

  function number(options?: Intl.NumberFormatOptions): Intl.NumberFormat {
    const key = JSON.stringify(options ?? null);
    let fmt = numberCache.get(key);
    if (!fmt) {
      fmt = new Intl.NumberFormat(tag, options);
      numberCache.set(key, fmt);
    }
    return fmt;
  }

  return {
    tag,
    formatDate: (date, options) => dateTime(options).format(date),
    formatTime: (date, options) => dateTime(options).format(date),
    formatDateTime: (date, options) => dateTime(options).format(date),
    formatNumber: (value, options) => number(options).format(value),
  };
}

const formattersByTag = new Map<string, LocaleFormatters>();

function getFormatters(tag: string): LocaleFormatters {
  let fmt = formattersByTag.get(tag);
  if (!fmt) {
    fmt = buildFormatters(tag);
    formattersByTag.set(tag, fmt);
  }
  return fmt;
}

/** Hook: locale-tagged Intl formatters following the active language. */
export function useLocale(): LocaleFormatters {
  const { i18n } = useTranslation();
  const language = i18n.resolvedLanguage ?? i18n.language ?? 'en';
  const tag = localeTag(language as Parameters<typeof localeTag>[0]) ?? 'en-US';
  return useMemo(() => getFormatters(tag), [tag]);
}

/**
 * Non-hook variant for plain modules that run outside React render
 * (table formatters, util functions). Resolves the active tag from the
 * i18n instance and shares the same per-tag formatter cache.
 */
export function activeLocaleFormatters(): LocaleFormatters {
  const language = i18next.language ?? i18next.resolvedLanguage ?? 'en';
  const tag = localeTag(language as Parameters<typeof localeTag>[0]) ?? 'en-US';
  return getFormatters(tag);
}

/** Convenience wrapper: locale-formatted number for plain module code. */
export function formatLocaleNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return activeLocaleFormatters().formatNumber(value, options);
}

/** Convenience wrapper: locale-formatted date-time for plain module code. */
export function formatLocaleDateTime(date: Date, options?: Intl.DateTimeFormatOptions): string {
  return activeLocaleFormatters().formatDateTime(date, options);
}

/** Active ICU locale tag (e.g. "de-DE") for non-hook call sites. */
export function activeLocaleTag(): string {
  return activeLocaleFormatters().tag;
}
