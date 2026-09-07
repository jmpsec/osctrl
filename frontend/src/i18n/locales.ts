/**
 * locales.ts — supported language registry.
 *
 * English is the source/fallback language and is bundled statically so the
 * app never flashes a wrong language while a chunk loads. Every other
 * language is a lazy Vite chunk (~a few KB gz) fetched once per browser
 * session on first switch, then served from the HTTP cache.
 */

export const DEFAULT_LANGUAGE = 'en' as const;

/** ISO code → ICU locale tag used by Intl formatters. */
const LOCALE_TAGS: Record<SupportedLanguage, string> = {
  en: 'en-US',
  es: 'es-ES',
  fr: 'fr-FR',
  de: 'de-DE',
  pt: 'pt-BR',
  ca: 'ca-ES',
  it: 'it-IT',
};

/** UI-facing language names, written in their own language (endonyms). */
const LANGUAGE_NAMES: Record<SupportedLanguage, string> = {
  en: 'English',
  es: 'Español',
  fr: 'Français',
  de: 'Deutsch',
  pt: 'Português',
  ca: 'Català',
  it: 'Italiano',
};

export const SUPPORTED_LANGUAGES = Object.freeze(
  Object.keys(LOCALE_TAGS) as SupportedLanguage[],
);

export type SupportedLanguage = 'en' | 'es' | 'fr' | 'de' | 'pt' | 'ca' | 'it';

export function isSupportedLanguage(value: string): value is SupportedLanguage {
  return SUPPORTED_LANGUAGES.includes(value as SupportedLanguage);
}

export function localeTag(language: SupportedLanguage): string {
  return LOCALE_TAGS[language];
}

export function languageName(language: SupportedLanguage): string {
  return LANGUAGE_NAMES[language];
}

/**
 * Resolve a raw BCP-47 tag (e.g. navigator.language: "es-MX", "de-AT")
 * to the closest supported language. Exact match wins, then the base
 * language, then undefined.
 */
export function matchLanguage(raw: string | undefined | null): SupportedLanguage | undefined {
  if (!raw) return undefined;
  // BCP-47 uses "-" (es-MX); some environments report "_" (fr_FR).
  const normalized = raw.trim().toLowerCase().replace('_', '-');
  if (isSupportedLanguage(normalized)) return normalized;
  const base = normalized.split('-')[0];
  if (isSupportedLanguage(base)) return base;
  return undefined;
}
