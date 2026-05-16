/**
 * design-tokens.ts — typed re-export of the brand tokens.
 * Mirrors src/styles/tokens.css; keep them in sync.
 */

export const fonts = {
  display: "'Space Grotesk', sans-serif",
  body: "'Inter', sans-serif",
  mono: "'IBM Plex Mono', ui-monospace, monospace",
} as const;

export const scale = {
  display: 48,
  h1: 32,
  h2: 24,
  h3: 18,
  body: 15,
  table: 13,
  caption: 12,
  label: 10,
} as const;

export const spacing = {
  1: 4,
  2: 8,
  3: 12,
  4: 16,
  6: 24,
  8: 32,
  12: 48,
} as const;

export const radius = {
  chip: 4,
  button: 8,
  card: 12,
  pill: 9999,
} as const;

export const motion = {
  fast: '120ms ease-out',
  base: '160ms ease-out',
  modal: '220ms cubic-bezier(0.3, 0.7, 0.2, 1)',
} as const;

/**
 * Color tokens — for consumption in TypeScript only.
 * In CSS, prefer `var(--token-name)` from tokens.css; that's the canonical
 * source. This object exists for places where TS needs hex (e.g. embedded
 * SVG props, canvas drawing, chart libraries).
 */
export const colors = {
  dark: {
    bg0: '#07090c',
    bg1: '#0c1014',
    bg2: '#11171d',
    bg3: '#18202a',
    border: '#1e2934',
    borderStrong: '#2a3845',
    text1: '#ecf1f6',
    text2: '#a6b3c0',
    text3: '#6a7886',
    textLink: '#5fb8ff',
    signal: '#2bc4be',
    signalBright: '#5fe3df',
    signalDeep: '#0a6b66',
    success: '#4ade80',
    warning: '#fbbf24',
    danger: '#f87171',
    info: '#67c0ff',
  },
  light: {
    bg0: '#f4f7f8',
    bg1: '#ffffff',
    bg2: '#f8fafb',
    bg3: '#edf1f3',
    border: '#e2e8ec',
    borderStrong: '#cfd8de',
    text1: '#0e1620',
    text2: '#495766',
    text3: '#7a8694',
    textLink: '#1f6fd9',
    signal: '#0a8a85',
    signalBright: '#14a8a3',
    signalDeep: '#074a48',
    success: '#16a34a',
    warning: '#d97706',
    danger: '#dc2626',
    info: '#2563eb',
  },
} as const;

export type Theme = 'dark' | 'light';
export const DEFAULT_THEME: Theme = 'dark';

/**
 * The single source of truth grouped object — useful for token-aware
 * generators (Storybook, chromatic, etc.).
 */
export const tokens = { fonts, scale, spacing, radius, motion, colors } as const;
