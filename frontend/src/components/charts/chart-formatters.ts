/**
 * Locale-aware chart formatters.
 *
 * The originals were module-level `Intl.DateTimeFormat` constants pinned
 * to "en-US". For i18n they must follow the active language, so each is
 * now a function resolving against the current i18n language. Formatter
 * objects are cached per (language, preset) pair — construction compiles
 * ICU patterns and is expensive; formatting itself is cheap, and charts
 * format thousands of ticks.
 */
import i18next from 'i18next';
import { localeTag, DEFAULT_LANGUAGE, type SupportedLanguage } from '$/i18n/locales';

function activeTag(): string {
  const language = (i18next.language ?? DEFAULT_LANGUAGE) as SupportedLanguage;
  return localeTag(language);
}

const dateCache = new Map<string, Intl.DateTimeFormat>();
const numberCache = new Map<string, Intl.NumberFormat>();

function cachedDate(tag: string, preset: string, options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = `${tag}:${preset}`;
  let fmt = dateCache.get(key);
  if (!fmt) {
    fmt = new Intl.DateTimeFormat(tag, options);
    dateCache.set(key, fmt);
  }
  return fmt;
}

/** "Mar 14"-style abbreviated date, locale-tagged. */
export function shortDateFmt(): Intl.DateTimeFormat {
  const tag = activeTag();
  return cachedDate(tag, 'shortDate', { month: 'short', day: 'numeric' });
}

/** "Fri, Mar 14"-style weekday + date, locale-tagged. */
export function weekdayDateFmt(): Intl.DateTimeFormat {
  const tag = activeTag();
  return cachedDate(tag, 'weekdayDate', { weekday: 'short', month: 'short', day: 'numeric' });
}

/** HH:MM:SS (24h), locale-tagged. */
export function hmsTimeFmt(): Intl.DateTimeFormat {
  const tag = activeTag();
  return cachedDate(tag, 'hmsTime', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

/** Locale-tagged integer formatter. */
export function intFmt(): Intl.NumberFormat {
  const tag = activeTag();
  let fmt = numberCache.get(tag);
  if (!fmt) {
    fmt = new Intl.NumberFormat(tag);
    numberCache.set(tag, fmt);
  }
  return fmt;
}
