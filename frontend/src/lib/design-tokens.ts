/**
 * design-tokens.ts — typed re-export of the brand tokens.
 * Mirrors src/styles/tokens.css; keep them in sync.
 */

export const fonts = {
  display: "'Inter', sans-serif",
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
  button: 6,
  card: 8,
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
    bg0: '#191919',
    bg1: '#171717',
    bg2: '#1b1b1b',
    bg3: '#232323',
    border: '#2b2b2b',
    borderStrong: '#484848',
    text1: '#ebebeb',
    text2: '#b3b3b3',
    text3: '#808080',
    text4: '#666666',
    textLink: '#8da4ff',
    accent: '#6e7ff2',
    accentHover: '#7f8ff7',
    signal: '#6e7ff2',
    signalBright: '#8da4ff',
    signalDeep: '#3e63dd',
    success: '#4ade80',
    warning: '#fbbf24',
    danger: '#f87171',
    info: '#67c0ff',
    navTeal: '#5eead4',
    navViolet: '#a78bfa',
    navRose: '#fb7185',
  },
  light: {
    bg0: '#f8f8f8',
    bg1: '#ffffff',
    bg2: '#fcfcfc',
    bg3: '#f1f1f1',
    border: '#eaeaea',
    borderStrong: '#d6d6d6',
    text1: '#333333',
    text2: '#666666',
    text3: '#999999',
    text4: '#b3b3b3',
    textLink: '#3e63dd',
    accent: '#3e63dd',
    accentHover: '#3451b2',
    signal: '#3e63dd',
    signalBright: '#3451b2',
    signalDeep: '#263ea5',
    success: '#16a34a',
    warning: '#d97706',
    danger: '#dc2626',
    info: '#2563eb',
    navTeal: '#0f766e',
    navViolet: '#7c3aed',
    navRose: '#e11d48',
  },
} as const;

export type Theme = 'dark' | 'light';
export const DEFAULT_THEME: Theme = 'dark';

/**
 * The single source of truth grouped object — useful for token-aware
 * generators (Storybook, chromatic, etc.).
 */
export const tokens = { fonts, scale, spacing, radius, motion, colors } as const;
