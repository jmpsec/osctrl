/**
 * Boot-preload regression test — kept in its own file with NO static
 * import of ./i18n: a static import would run the boot sequence (and
 * initialize the shared i18next singleton) before the test seeds
 * localStorage, so the re-import's init() would hit an already-
 * initialized singleton. Importing only after seeding + resetModules
 * replays the boot exactly as a real page load does.
 */
import { describe, it, expect, vi } from 'vitest';
import { useLocalStorageStub } from '$/lib/test-storage';

// Mirror writes go through the API client; stub the module so no
// network (or CSRF dance) happens in tests. vi.mock is hoisted.
vi.mock('$/api/users', () => ({
  patchMe: vi.fn().mockResolvedValue({}),
}));

const STORAGE_KEY = 'osctrl.language';

describe('boot language preload', () => {
  useLocalStorageStub();

  it('renders the stored language on load instead of falling back to English', async () => {
    // Regression: boot initialized i18next with lng='es' (from the
    // stored preference) but never loaded the Spanish catalog chunk —
    // every key silently fell back to English on page load, and
    // reconcile was a no-op because both sides agreed.
    window.localStorage.setItem(STORAGE_KEY, 'es');
    vi.resetModules();
    const mod = await import('./i18n');

    // The boot preload is sequenced after the async i18next init +
    // dynamic chunk import; poll until it lands. The real UI flips
    // reactively at the same point, so this mirrors production.
    let ok = false;
    for (let i = 0; i < 200; i++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      if (mod.i18n.t('common.signOut') === 'Cerrar sesión') { ok = true; break; }
    }
    expect(ok).toBe(true);
    expect(mod.i18n.language).toBe('es');
    expect(mod.i18n.t('nav.nodes')).toBe('Nodos');
    expect(document.documentElement.getAttribute('lang')).toBe('es');

    // Reconcile with the same value stays a no-op but keeps Spanish
    // (previously the early return skipped ensuring the catalog).
    await mod.reconcileLanguageFromServer('es');
    expect(mod.i18n.t('common.signOut')).toBe('Cerrar sesión');

    // The reconcile no-op path must not echo a PATCH for the boot value.
    const { patchMe } = await import('$/api/users');
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(patchMe).not.toHaveBeenCalled();
  });
});

describe('boot language preload (english)', () => {
  useLocalStorageStub();

  it('boots straight into English when that is what is stored', async () => {
    window.localStorage.setItem(STORAGE_KEY, 'en');
    vi.resetModules();
    const mod = await import('./i18n');
    for (let i = 0; i < 200; i++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      if (mod.i18n.t('common.signOut') === 'Sign out') break;
    }
    expect(mod.i18n.language).toBe('en');
    expect(mod.i18n.t('common.signOut')).toBe('Sign out');
  });
});
