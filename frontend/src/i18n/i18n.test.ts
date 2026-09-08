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
  languageFlag,
  SUPPORTED_LANGUAGES,
} from './locales';
import { en } from './locales/en/common';
import { es } from './locales/es/common';
import { fr } from './locales/fr/common';
import { de } from './locales/de/common';
import { pt } from './locales/pt/common';
import { ca } from './locales/ca/common';
import { it as itCatalog } from './locales/it/common';
import { nl } from './locales/nl/common';
import { ja } from './locales/ja/common';
import { ko } from './locales/ko/common';
import { zh } from './locales/zh/common';
import { pl } from './locales/pl/common';
import { ru } from './locales/ru/common';
import { fa } from './locales/fa/common';
import { ar } from './locales/ar/common';
import { hi } from './locales/hi/common';

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
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'xx');
    expect(getInitialLanguage()).not.toBe('xx');
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
    expect(matchLanguage('xx')).toBeUndefined();
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
    await setLanguage('xx');
    expect(i18n.language).toBe('en');
    expect(isSupportedLanguage('xx')).toBe(false);
  });
});

describe('catalog completeness', () => {
  const englishKeys = keyPaths(en);

  it('has exactly the supported language set', () => {
    expect([...SUPPORTED_LANGUAGES].sort()).toEqual([
      'ar', 'ca', 'de', 'en', 'es', 'fa', 'fr', 'hi', 'it', 'ja',
      'ko', 'nl', 'pl', 'pt', 'ru', 'zh',
    ]);
  });

  it.each([
    ['es', es],
    ['fr', fr],
    ['de', de],
    ['pt', pt],
    ['ca', ca],
    ['it', itCatalog],
    ['nl', nl],
    ['ja', ja],
    ['ko', ko],
    ['zh', zh],
    ['pl', pl],
    ['ru', ru],
    ['fa', fa],
    ['ar', ar],
    ['hi', hi],
  ] as const)('%s catalog mirrors every English key', (_language, catalog) => {
    const paths = keyPaths(catalog);
    expect(paths.sort()).toEqual([...englishKeys].sort());
  });

  it('has no empty translations', () => {
    for (const catalog of [es, fr, de, pt, ca, itCatalog, nl, ja, ko, zh, pl, ru, fa, ar, hi]) {
      for (const path of keyPaths(catalog)) {
        const value = path
          .split('.')
          .reduce<unknown>((acc, key) => (acc as Record<string, unknown>)[key], catalog);
        expect(typeof value).toBe('string');
        expect((value as string).length).toBeGreaterThan(0);
      }
    }
  });

  it('assigns a flag emoji to every language', () => {
    for (const language of SUPPORTED_LANGUAGES) {
      const flag = languageFlag(language);
      // Regional-indicator pairs: two code points in the U+1F1E6–1F1FF
      // range, forming a flag sequence in any emoji-capable renderer.
      expect([...flag]).toHaveLength(2);
      for (const char of [...flag]) {
        const code = char.codePointAt(0)!;
        expect(code).toBeGreaterThanOrEqual(0x1f1e6);
        expect(code).toBeLessThanOrEqual(0x1f1ff);
      }
    }
  });
});
