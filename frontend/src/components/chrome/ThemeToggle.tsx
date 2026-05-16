import { useEffect, useState } from 'react';
import { cn } from '$/lib/cn';
import { toggleTheme, getInitialTheme, applyTheme } from '$/lib/theme';
import type { Theme } from '$/lib/design-tokens';

export function ThemeToggle() {
  const [current, setCurrent] = useState<Theme>(() => {
    const fromDom = document.documentElement.getAttribute('data-theme') as Theme | null;
    return fromDom === 'light' || fromDom === 'dark' ? fromDom : getInitialTheme();
  });

  useEffect(() => {
    applyTheme(current);
  }, [current]);

  function handleToggle(theme: 'dark' | 'light') {
    if (theme === current) return;
    const next = toggleTheme();
    setCurrent(next);
  }

  return (
    <div
      role="group"
      aria-label="Toggle color theme"
      className={cn(
        'flex items-center gap-0.5 p-1 rounded-full',
        'bg-[color:var(--bg-1)] border border-[color:var(--border)]',
      )}
    >
      {(['dark', 'light'] as const).map((theme) => (
        <button
          key={theme}
          onClick={() => handleToggle(theme)}
          aria-pressed={current === theme}
          className={cn(
            'px-2.5 py-1 rounded-full text-[11px] font-medium font-mono-tabular uppercase tracking-[0.04em]',
            'transition-colors duration-[120ms] ease-out',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
            current === theme
              ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]'
              : 'text-[color:var(--text-2)] hover:text-[color:var(--text-1)]'
          )}
        >
          {theme.toUpperCase()}
        </button>
      ))}
    </div>
  );
}
