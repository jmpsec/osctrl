import { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '$/lib/cn';
import { toggleTheme, getInitialTheme, applyTheme } from '$/lib/theme';
import type { Theme } from '$/lib/design-tokens';

export function ThemeToggle() {
  const { t } = useTranslation();
  const [current, setCurrent] = useState<Theme>(() => {
    const fromDom = document.documentElement.getAttribute('data-theme') as Theme | null;
    return fromDom === 'light' || fromDom === 'dark' ? fromDom : getInitialTheme();
  });

  useEffect(() => {
    applyTheme(current);
  }, [current]);

  function handleToggle() {
    const next = toggleTheme();
    setCurrent(next);
  }

  const nextThemeLabel = current === 'dark' ? t('theme.toLight') : t('theme.toDark');
  return (
    <button
      type="button"
      onClick={handleToggle}
      aria-label={nextThemeLabel}
      title={nextThemeLabel}
      className={cn(
        'flex h-8 w-8 items-center justify-center rounded-md',
        'text-[color:var(--text-3)] hover:bg-[color:var(--bg-3)] hover:text-[color:var(--text-1)]',
        'transition-colors duration-[100ms]',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--accent)]',
      )}
    >
      {current === 'dark' ? <Sun size={16} strokeWidth={1.75} /> : <Moon size={16} strokeWidth={1.75} />}
    </button>
  );
}
