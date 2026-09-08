import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  i18n,
  LANGUAGE_STORAGE_KEY,
  reconcileLanguageFromServer,
  setLanguage,
  setLanguageEphemeral,
} from './i18n';
import { useLocalStorageStub } from '$/lib/test-storage';

// Mirror writes go through the API client; stub the module so no
// network (or CSRF dance) happens in tests. vi.mock is hoisted.
vi.mock('$/api/users', () => ({
  patchMe: vi.fn().mockResolvedValue({}),
}));

describe('cross-device language sync', () => {
  useLocalStorageStub();

  beforeEach(async () => {
    vi.clearAllMocks();
    window.localStorage.clear();
    await setLanguageEphemeral('en');
  });

  it('applies the server preference when the local value differs', async () => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'en');
    await reconcileLanguageFromServer('fr');
    expect(i18n.language).toBe('fr');
    expect(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('fr');
    expect(document.documentElement.getAttribute('lang')).toBe('fr');
  });

  it('is a no-op when both sides agree', async () => {
    await setLanguageEphemeral('de');
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'de');
    await reconcileLanguageFromServer('de');
    expect(i18n.language).toBe('de');
  });

  it('ignores unsupported server values', async () => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'en');
    await reconcileLanguageFromServer('xx');
    expect(i18n.language).toBe('en');
  });

  it('ignores an empty server preference', async () => {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, 'es');
    await setLanguageEphemeral('es');
    await reconcileLanguageFromServer('');
    expect(i18n.language).toBe('es');
  });

  it('mirrors explicit switches to the server via patchMe', async () => {
    const { patchMe } = await import('$/api/users');
    await setLanguage('it');
    // The mirror is fire-and-forget; let the microtask queue drain.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(patchMe).toHaveBeenCalledWith({ preferred_language: 'it' });
  });

  it('does not re-mirror the same language twice', async () => {
    const { patchMe } = await import('$/api/users');
    await setLanguage('ru');
    await setLanguage('ru');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(patchMe).toHaveBeenCalledTimes(1);
  });

  it('survives a failed mirror without changing the active language', async () => {
    const { patchMe } = await import('$/api/users');
    (patchMe as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('offline'));
    await setLanguage('ja');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(i18n.language).toBe('ja');
    expect(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('ja');
  });
});
