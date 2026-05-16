import { describe, it, expect } from 'vitest';
import { tokens, colors, fonts, motion } from './design-tokens';

describe('design tokens', () => {
  it('has dark + light color palettes with matching keys', () => {
    const darkKeys = Object.keys(colors.dark).sort();
    const lightKeys = Object.keys(colors.light).sort();
    expect(lightKeys).toEqual(darkKeys);
  });

  it('exposes signal, success, warning, danger, info in both themes', () => {
    const required = ['signal', 'success', 'warning', 'danger', 'info'];
    for (const t of ['dark', 'light'] as const) {
      for (const k of required) {
        expect(colors[t]).toHaveProperty(k);
      }
    }
  });

  it('exposes the three brand fonts', () => {
    expect(fonts.display).toContain('Space Grotesk');
    expect(fonts.body).toContain('Inter');
    expect(fonts.mono).toContain('IBM Plex Mono');
  });

  it('motion timings are valid CSS', () => {
    expect(motion.fast).toMatch(/^\d+ms /);
    expect(motion.base).toMatch(/^\d+ms /);
    expect(motion.modal).toMatch(/^\d+ms /);
  });

  it('tokens is a frozen-shape object', () => {
    expect(tokens.fonts).toBe(fonts);
    expect(tokens.colors).toBe(colors);
  });
});
