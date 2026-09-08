import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LanguageMenu } from './LanguageMenu';
import { i18n, LANGUAGE_STORAGE_KEY, setLanguageEphemeral } from '$/i18n/i18n';
import { useLocalStorageStub } from '$/lib/test-storage';
import { SUPPORTED_LANGUAGES } from '$/i18n/locales';

describe('LanguageMenu', () => {
  useLocalStorageStub();

  beforeEach(async () => {
    await setLanguageEphemeral('en');
  });

  it('renders every supported language with its flag', async () => {
    const user = userEvent.setup();
    render(<LanguageMenu />);

    await user.click(screen.getByRole('button', { name: 'Change language' }));

    const menu = screen.getByRole('menu');
    for (const name of [
      'English', 'Español', 'Français', 'Deutsch', 'Português', 'Català', 'Italiano',
      'Nederlands', '日本語', '한국어', '中文', 'Polski', 'Русский', 'فارسی', 'العربية',
      'हिन्दी', 'עברית', 'Türkçe', 'Українська', 'Ελληνικά',
    ]) {
      expect(within(menu).getByText(name)).toBeInTheDocument();
    }
    // Flags render as decorated spans next to each name.
    expect(within(menu).getAllByText('🇬🇧').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇵🇹').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇦🇩').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇷🇺').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇮🇷').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇸🇦').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇮🇳').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇮🇱').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇹🇷').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇺🇦').length).toBeGreaterThanOrEqual(1);
    expect(within(menu).getAllByText('🇬🇷').length).toBeGreaterThanOrEqual(1);
    expect(SUPPORTED_LANGUAGES).toHaveLength(20);
  });

  it('flips the document direction for RTL languages and back', async () => {
    const user = userEvent.setup();
    render(<LanguageMenu />);

    await user.click(screen.getByRole('button', { name: 'Change language' }));
    await user.click(within(screen.getByRole('menu')).getByText('العربية'));

    expect(await screen.findByRole('button', { name: 'تغيير اللغة' })).toBeInTheDocument();
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');

    // Hebrew is also RTL.
    await user.click(screen.getByRole('button', { name: 'تغيير اللغة' }));
    await user.click(within(screen.getByRole('menu')).getByText('עברית'));

    expect(await screen.findByRole('button', { name: 'שינוי שפה' })).toBeInTheDocument();
    expect(document.documentElement.getAttribute('dir')).toBe('rtl');

    await user.click(screen.getByRole('button', { name: 'שינוי שפה' }));
    await user.click(within(screen.getByRole('menu')).getByText('English'));

    expect(await screen.findByRole('button', { name: 'Change language' })).toBeInTheDocument();
    expect(document.documentElement.getAttribute('dir')).toBe('ltr');
  });

  it('switches the active language and persists the choice', async () => {
    const user = userEvent.setup();
    render(<LanguageMenu />);

    await user.click(screen.getByRole('button', { name: 'Change language' }));
    await user.click(within(screen.getByRole('menu')).getByText('Español'));

    // The button's own label is now translated.
    expect(await screen.findByRole('button', { name: 'Cambiar idioma' })).toBeInTheDocument();
    expect(i18n.language).toBe('es');
    expect(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)).toBe('es');
    expect(document.documentElement.getAttribute('lang')).toBe('es');
  });

  it('reverts to English and keeps the fallback working', async () => {
    await setLanguageEphemeral('de');
    const user = userEvent.setup();
    render(<LanguageMenu />);

    await user.click(screen.getByRole('button', { name: 'Sprache ändern' }));
    await user.click(within(screen.getByRole('menu')).getByText('English'));

    expect(await screen.findByRole('button', { name: 'Change language' })).toBeInTheDocument();
    expect(i18n.language).toBe('en');
  });
});
