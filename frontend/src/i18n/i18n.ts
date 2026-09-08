/**
 * i18n.ts — i18next instance and language lifecycle.
 *
 * Resolution order (mirrors lib/theme.ts so both preferences behave the
 * same at boot, with no flash of wrong language):
 *   1. localStorage["osctrl.language"]   — user's explicit choice
 *   2. navigator.languages                 — browser preference (base match)
 *   3. "en"                                — fallback/source language
 *
 * English catalogs are bundled in the main chunk (they are the fallback),
 * every other language is a lazy Vite chunk fetched once on first switch.
 */

import i18next, { type i18n as I18n } from 'i18next';
import { initReactI18next } from 'react-i18next';
import ICU from 'i18next-icu';
import { en } from './locales/en/common';
import {
  DEFAULT_LANGUAGE,
  isSupportedLanguage,
  isRTL,
  matchLanguage,
  type SupportedLanguage,
} from './locales';

export const LANGUAGE_STORAGE_KEY = 'osctrl.language';

/** Lazy catalog loaders — Vite turns each into a separate chunk. */
type CatalogModule = {
  en?: unknown;
  es?: unknown;
  fr?: unknown;
  de?: unknown;
  pt?: unknown;
  ca?: unknown;
  it?: unknown;
  nl?: unknown;
  ja?: unknown;
  ko?: unknown;
  zh?: unknown;
  pl?: unknown;
  ru?: unknown;
  fa?: unknown;
  ar?: unknown;
  hi?: unknown;
};

const catalogs: Record<SupportedLanguage, () => Promise<CatalogModule>> = {
  en: () => Promise.resolve({ en }),
  es: () => import('./locales/es/common'),
  fr: () => import('./locales/fr/common'),
  de: () => import('./locales/de/common'),
  pt: () => import('./locales/pt/common'),
  ca: () => import('./locales/ca/common'),
  it: () => import('./locales/it/common'),
  nl: () => import('./locales/nl/common'),
  ja: () => import('./locales/ja/common'),
  ko: () => import('./locales/ko/common'),
  zh: () => import('./locales/zh/common'),
  pl: () => import('./locales/pl/common'),
  ru: () => import('./locales/ru/common'),
  fa: () => import('./locales/fa/common'),
  ar: () => import('./locales/ar/common'),
  hi: () => import('./locales/hi/common'),
};

/** Languages whose catalog is already loaded (or being loaded). */
const loaded = new Set<SupportedLanguage>([DEFAULT_LANGUAGE]);

export function getInitialLanguage(): SupportedLanguage {
  if (typeof window === 'undefined') return DEFAULT_LANGUAGE;
  try {
    const stored = window.localStorage?.getItem(LANGUAGE_STORAGE_KEY);
    if (stored && isSupportedLanguage(stored)) return stored;
  } catch {
    /* localStorage blocked — fall through to navigator detection */
  }
  for (const tag of navigator.languages ?? []) {
    const matched = matchLanguage(tag);
    if (matched) return matched;
  }
  return DEFAULT_LANGUAGE;
}

async function loadCatalog(language: SupportedLanguage): Promise<void> {
  if (loaded.has(language)) return;
  loaded.add(language);
  try {
    const mod = await catalogs[language]();
    // Every catalog module exports its bundle under a named export
    // matching its own language code (`export const es`, etc.).
    const bundle = (mod as Record<string, Record<string, unknown>>)[language];
    i18next.addResourceBundle(language, 'translation', bundle, true, true);
  } catch (err) {
    loaded.delete(language);
    throw err;
  }
}

/**
 * Switch the active language, loading its catalog chunk if needed.
 * Resolves only after the UI language has actually flipped, so callers
 * can treat failures (network) as "language unchanged".
 *
 * `mirror` (default true) additionally persists the choice server-side
 * via PATCH /users/me so it follows the operator across devices.
 * Pass false for boot-time reconciliation, where applying the server
 * value must not echo back a redundant write.
 */
export async function setLanguage(language: SupportedLanguage, mirror = true): Promise<void> {
  if (!isSupportedLanguage(language)) return;
  if (i18next.language !== language) await loadCatalog(language);
  await i18next.changeLanguage(language);
  applyLanguageSideEffects(language);
  try {
    window.localStorage?.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    /* localStorage blocked — session-only preference */
  }
  if (mirror) void mirrorLanguageToServer(language);
}

/** Local cache of the last value we pushed to / saw from the server. */
let mirroredLanguage: string | null = null;

async function mirrorLanguageToServer(language: SupportedLanguage): Promise<void> {
  if (mirroredLanguage === language) return;
  mirroredLanguage = language;
  try {
    const { patchMe } = await import('$/api/users');
    await patchMe({ preferred_language: language });
  } catch {
    // Offline, 401, or API unreachable — the local preference still
    // applies for this session; retried on the next explicit switch.
    mirroredLanguage = null;
  }
}

/**
 * Reconcile the local language preference with the operator's
 * server-side PreferredLanguage (from GET /users/me).
 *
 * localStorage is the boot source (it is available synchronously before
 * first paint); this runs once the profile query resolves and makes the
 * server the tie-breaker: the server value reflects the most recent
 * explicit choice on ANY device, because every switch mirrors to it.
 *
 * The applied value is recorded in `mirroredLanguage` so the switch is
 * not echoed back as a redundant PATCH.
 */
export async function reconcileLanguageFromServer(
  serverLanguage: string,
): Promise<void> {
  if (!serverLanguage) return;
  let language: SupportedLanguage | undefined;
  try {
    const stored = window.localStorage?.getItem(LANGUAGE_STORAGE_KEY);
    if (stored === serverLanguage) return;
  } catch {
    /* localStorage blocked — fall through and apply the server value */
  }
  language = matchLanguage(serverLanguage);
  if (!language) return;
  mirroredLanguage = language;
  try {
    window.localStorage?.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    /* localStorage blocked — session-only preference */
  }
  if (i18next.language !== language) {
    await loadCatalog(language);
    await i18next.changeLanguage(language);
    applyLanguageSideEffects(language);
  }
}

/** Non-persisting variant used by the test setup and SSR-ish contexts. */
export async function setLanguageEphemeral(language: SupportedLanguage): Promise<void> {
  if (!isSupportedLanguage(language)) return;
  if (i18next.language !== language) await loadCatalog(language);
  await i18next.changeLanguage(language);
  applyLanguageSideEffects(language);
}

function applyLanguageSideEffects(language: SupportedLanguage): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('lang', language);
  // RTL languages mirror the entire UI; anything else resets to LTR
  // so switching back does not leave a stale direction behind.
  document.documentElement.setAttribute('dir', isRTL(language) ? 'rtl' : 'ltr');
}

const initial = getInitialLanguage();

export const i18n: I18n = i18next;

// initReactI18next wires the instance into useTranslation via a context.
void i18next
  .use(initReactI18next)
  .use(ICU)
  .init({
    lng: initial,
    fallbackLng: DEFAULT_LANGUAGE,
    // The lazy-load path calls addResourceBundle manually, so i18next
    // must not try to fetch resources through a backend. The English
    // bundle is passed here (already imported) so the default language
    // renders without any asynchronous work.
    resources: {
      en: { translation: en },
    },
    interpolation: {
      // React already escapes anything rendered into the DOM.
      escapeValue: false,
    },
    returnEmptyString: false,
  });

// Ensure the html lang attribute matches even before first switch
// (getInitialLanguage may resolve to a navigator-detected language
// whose lazy chunk is not needed yet — the attribute is free).
applyLanguageSideEffects(initial);
