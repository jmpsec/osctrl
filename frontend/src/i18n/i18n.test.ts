import { describe, it, expect, beforeEach } from 'vitest';
import { useLocalStorageStub } from '$/lib/test-storage';
import {
  getInitialLanguage,
  i18n,
  LANGUAGE_STORAGE_KEY,
  setLanguage,
  setLanguageEphemeral,
} from './i18n';
import {
  DEFAULT_LANGUAGE,
  isSupportedLanguage,
  matchLanguage,
  SUPPORTED_LANGUAGES,
} from './locales';
import { en } from './locales/en/common';
import { es } from './locales/es/common';
import { fr } from './locales/fr/common';
import { de } from './locales/de/common';
import { pt } from './locales/pt/common';
import { ca } from './locales/ca/common';
import { it as itCatalog } from './locales/it/common';

/** Recursively collect every key path ("a.b.c") from a catalog object. */
function keyPaths(obj: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(obj).flatMap(([key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return typeof value === 'object' && value !== null
      ? keyPaths(value as Record<string, unknown>, path)
      : [path];
  });
}

describe('i18n language resolution', () => {
  useLocalStorageStub();

  beforeEach(() => {
    window.localStorage.clear();
  });

  it('uses the stored language when valid', () => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'fr');
    expect(getInitialLanguage()).toBe('fr');
  });

  it('ignores an unsupported stored language', () => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'ja');
    expect(getInitialLanguage()).not.toBe('ja');
  });

  it('falls back to the default language with no signal', () => {
    const original = navigator.languages;
    Object.defineProperty(window.navigator, 'languages', {
      configurable: true,
      value: [],
    });
    try {
      expect(getInitialLanguage()).toBe(DEFAULT_LANGUAGE);
    } finally {
      Object.defineProperty(window.navigator, 'languages', {
        configurable: true,
        value: original,
      });
    }
  });
});

describe('matchLanguage', () => {
  it('matches exact codes and base languages', () => {
    expect(matchLanguage('es')).toBe('es');
    expect(matchLanguage('es-MX')).toBe('es');
    expect(matchLanguage('de-AT')).toBe('de');
    expect(matchLanguage('fr_FR')).toBe('fr');
    expect(matchLanguage('pt-BR')).toBe('pt');
    expect(matchLanguage('ca-ES')).toBe('ca');
    expect(matchLanguage('it-IT')).toBe('it');
  });

  it('returns undefined for unsupported languages', () => {
    expect(matchLanguage('ja')).toBeUndefined();
    expect(matchLanguage('')).toBeUndefined();
    expect(matchLanguage(undefined)).toBeUndefined();
  });
});

describe('language switching', () => {
  useLocalStorageStub();

  beforeEach(async () => {
    await setLanguageEphemeral('en');
  });

  it('switches language, translates, and persists', async () => {
    await setLanguage('de');
    expect(i18n.t('nav.nodes')).toBe('Knoten');
    expect(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('de');
    expect(document.documentElement.getAttribute('lang')).toBe('de');
  });

  it('keeps the previous language intact when switching back', async () => {
    await setLanguage('es');
    expect(i18n.t('common.signOut')).toBe('Cerrar sesión');
    await setLanguage('en');
    expect(i18n.t('common.signOut')).toBe('Sign out');
  });

  it('does not persist with the ephemeral variant', async () => {
    await setLanguageEphemeral('fr');
    expect(i18n.language).toBe('fr');
    expect(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBeNull();
  });

  it('ignores unsupported languages', async () => {
    await setLanguageEphemeral('en');
    // @ts-expect-error intentionally invalid language
    await setLanguage('ja');
    expect(i18n.language).toBe('en');
    expect(isSupportedLanguage('ja')).toBe(false);
  });
});

describe('catalog completeness', () => {
  const englishKeys = keyPaths(en);

  it('has exactly the supported language set', () => {
    expect([...SUPPORTED_LANGUAGES].sort()).toEqual(['ca', 'de', 'en', 'es', 'fr', 'it', 'pt']);
  });

  it.each([
    ['es', es],
    ['fr', fr],
    ['de', de],
    ['pt', pt],
    ['ca', ca],
    ['it', itCatalog],
  ] as const)('%s catalog mirrors every English key', (_language, catalog) => {
    const paths = keyPaths(catalog);
    expect(paths.sort()).toEqual([...englishKeys].sort());
  });

  it('has no empty translations', () => {
    for (const catalog of [es, fr, de, pt, ca, itCatalog]) {
      for (const path of keyPaths(catalog)) {
        const value = path
          .split('.')
          .reduce<unknown>((acc, key) => (acc as Record<string, unknown>)[key], catalog);
        expect(typeof value).toBe('string');
        expect((value as string).length).toBeGreaterThan(0);
      }
    }
  });
});
