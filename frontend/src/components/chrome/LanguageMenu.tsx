/**
 * LanguageMenu — per-user language selector.
 *
 * Follows the ThemeToggle pattern (localStorage-backed preference, see
 * i18n/i18n.ts) and reuses the Radix DropdownMenu primitive like
 * UserMenu. Switching is async (lazy catalog chunk for non-English);
 * the old language stays rendered until the new catalog is ready so
 * there is no flash of keys or English while a chunk is in flight.
 */
import { useState } from 'react';
import { Check, Languages } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '$/lib/cn';
import { DropdownMenu } from '$/components/primitives/DropdownMenu';
import {
  setLanguage,
} from '$/i18n/i18n';
import {
  SUPPORTED_LANGUAGES,
  languageName,
  type SupportedLanguage,
} from '$/i18n/locales';

export function LanguageMenu() {
  const { t, i18n } = useTranslation();
  const current = i18n.resolvedLanguage ?? i18n.language ?? 'en';
  const [busy, setBusy] = useState<SupportedLanguage | null>(null);

  async function handleChange(next: SupportedLanguage) {
    if (next === current || busy) return;
    setBusy(next);
    try {
      await setLanguage(next);
    } catch {
      // Catalog chunk failed to load (offline, CSP regression). The
      // active language is unchanged; the menu simply stays put.
    } finally {
      setBusy(null);
    }
  }

  const triggerClass = cn(
    'flex h-8 w-8 items-center justify-center rounded-md',
    'text-[color:var(--text-3)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
    'transition-colors duration-[100ms]',
    'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--accent)]',
  );

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button type="button" aria-label={t('language.changeLanguage')} title={t('language.changeLanguage')} className={triggerClass}>
          <Languages size={16} strokeWidth={1.75} />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Content align="end" sideOffset={8}>
        <DropdownMenu.Label>{t('language.changeLanguage')}</DropdownMenu.Label>
        <DropdownMenu.RadioGroup
          value={current}
          onValueChange={(value) => void handleChange(value as SupportedLanguage)}
        >
          {SUPPORTED_LANGUAGES.map((language) => (
            <DropdownMenu.RadioItem
              key={language}
              value={language}
              disabled={busy !== null && busy !== language}
              aria-current={current === language ? 'true' : undefined}
            >
              <span className="flex items-center gap-2">
                {languageName(language)}
                {busy === language && (
                  <span className="text-xs text-[color:var(--text-3)]">…</span>
                )}
              </span>
            </DropdownMenu.RadioItem>
          ))}
        </DropdownMenu.RadioGroup>
      </DropdownMenu.Content>
    </DropdownMenu.Root>
  );
}
