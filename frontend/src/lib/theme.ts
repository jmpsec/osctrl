/**
 * theme.ts — read/write the current theme. Theme switching = flipping
 * data-theme on <html>. Persisted in localStorage so the choice survives
 * reloads.
 */

import { DEFAULT_THEME, type Theme } from './design-tokens';

const STORAGE_KEY = 'osctrl.theme';

export function getInitialTheme(): Theme {
  if (typeof window === 'undefined') return DEFAULT_THEME;
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === 'dark' || stored === 'light') return stored;
  // first visit: follow system preference
  if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return 'light';
  return DEFAULT_THEME;
}

export function applyTheme(theme: Theme): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', theme);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* localStorage blocked — fail open */
  }
}

export function toggleTheme(): Theme {
  const next: Theme =
    document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  applyTheme(next);
  return next;
}
