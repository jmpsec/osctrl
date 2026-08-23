import { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
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

  function handleToggle() {
    const next = toggleTheme();
    setCurrent(next);
  }

  return (
    <button
      type="button"
      onClick={handleToggle}
      aria-label={`Switch to ${current === 'dark' ? 'light' : 'dark'} theme`}
      title={`Switch to ${current === 'dark' ? 'light' : 'dark'} theme`}
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
