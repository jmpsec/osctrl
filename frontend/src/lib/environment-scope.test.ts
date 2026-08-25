import { beforeEach, describe, expect, it } from 'vitest';
import { readActiveEnvironment, writeActiveEnvironment } from './environment-scope';

describe('environment scope persistence', () => {
  const values = new Map<string, string>();

  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
      clear: () => values.clear(),
      key: (index: number) => [...values.keys()][index] ?? null,
      get length() {
        return values.size;
      },
    } satisfies Storage,
  });

  beforeEach(() => values.clear());

  it('remembers the selected environment across global routes', () => {
    writeActiveEnvironment('production');
    expect(readActiveEnvironment()).toBe('production');
  });

  it('does not replace the active environment with an empty value', () => {
    writeActiveEnvironment('production');
    writeActiveEnvironment('');
    expect(readActiveEnvironment()).toBe('production');
  });
});
