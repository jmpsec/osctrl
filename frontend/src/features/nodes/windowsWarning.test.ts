import { describe, expect, it } from 'vitest';
import { isWindows } from './windowsWarning';

describe('isWindows', () => {
  it.each([
    ['windows', true],
    ['Windows', true],
    ['WIN', true],
    ['Win32', true],
    ['win64', true],
    ['ubuntu', false],
    ['darwin', false],
    ['', false],
    [undefined, false],
  ])('%s -> %s', (platform, want) => {
    expect(isWindows(platform)).toBe(want);
  });
});
