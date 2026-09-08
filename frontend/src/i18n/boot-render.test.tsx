import { createElement } from 'react';
import { act, cleanup, render, screen } from '@testing-library/react';
import { useTranslation } from 'react-i18next';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useLocalStorageStub } from '$/lib/test-storage';

describe('lazy language startup', () => {
  useLocalStorageStub();

  let releasePending: (() => void) | undefined;

  afterEach(async () => {
    cleanup();
    releasePending?.();
    await vi.dynamicImportSettled();
    vi.doUnmock('./locales/es/common');
    vi.doUnmock('i18next');
  });

  async function bootSpanish() {
    window.localStorage.setItem('osctrl.language', 'es');
    vi.resetModules();
    vi.doMock('i18next', async () => {
      const actual = await vi.importActual<typeof import('i18next')>('i18next');
      return { ...actual, default: actual.createInstance() };
    });
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    releasePending = release;
    vi.doMock('./locales/es/common', async () => {
      await pending;
      return vi.importActual('./locales/es/common');
    });
    const mod = await import('./i18n');
    function Label() {
      const { t, i18n } = useTranslation(undefined, { i18n: mod.i18n });
      return createElement('span', { lang: i18n.resolvedLanguage }, t('common.signOut'));
    }
    render(createElement(Label));
    expect(screen.getByText('Sign out')).toBeInTheDocument();
    return { ...mod, release };
  }

  it('updates mounted React text when the stored Spanish catalog arrives', async () => {
    const mod = await bootSpanish();
    await act(async () => {
      mod.release();
      await vi.dynamicImportSettled();
    });
    expect(await screen.findByText('Cerrar sesión')).toBeInTheDocument();
    expect(screen.getByText('Cerrar sesión')).toHaveAttribute('lang', 'es');
    expect(mod.i18n.resolvedLanguage).toBe('es');
    expect(mod.i18n.getResource('es', 'translation', 'common.signOut')).toBe('Cerrar sesión');
    expect(mod.i18n.t('common.signOut')).toBe('Cerrar sesión');
  });

  it('waits for a pending Spanish catalog when profile reconciliation agrees', async () => {
    const mod = await bootSpanish();
    let settled = false;
    const reconciliation = mod.reconcileLanguageFromServer('es').then(() => { settled = true; });
    await act(async () => { await Promise.resolve(); });
    expect(settled).toBe(false);
    await act(async () => {
      mod.release();
      await reconciliation;
      await vi.dynamicImportSettled();
    });
    expect(await screen.findByText('Cerrar sesión')).toBeInTheDocument();
  });

  it('does not overwrite a newer language choice with a slow boot catalog', async () => {
    const mod = await bootSpanish();
    await act(async () => { await mod.setLanguage('en', false); });
    await act(async () => {
      mod.release();
      await vi.dynamicImportSettled();
    });
    expect(screen.getByText('Sign out')).toBeInTheDocument();
    expect(mod.i18n.language).toBe('en');
    expect(document.documentElement.lang).toBe('en');
    expect(window.localStorage.getItem('osctrl.language')).toBe('en');
  });
});
