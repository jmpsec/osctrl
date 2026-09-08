import { describe, it, vi, expect } from 'vitest';
import { useLocalStorageStub } from '$/lib/test-storage';

vi.mock('$/api/users', () => ({ patchMe: vi.fn().mockResolvedValue({}) }));

describe('boot debug 3', () => {
  useLocalStorageStub();

  it('with reconcile part', async () => {
    window.localStorage.setItem('osctrl.language', 'es');
    vi.resetModules();
    const mod = await import('./i18n');
    for (let i = 0; i < 50; i++) {
      await new Promise((r) => setTimeout(r, 10));
      if (mod.i18n.t('common.signOut') === 'Cerrar sesión') break;
    }
    console.log('after poll:', mod.i18n.language, mod.i18n.t('common.signOut'));
    await mod.reconcileLanguageFromServer('es');
    console.log('after reconcile:', mod.i18n.language, mod.i18n.t('common.signOut'));
    expect(mod.i18n.t('common.signOut')).toBe('Cerrar sesión');
  });
});
