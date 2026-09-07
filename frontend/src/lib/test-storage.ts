/**
 * localStorage stub shared by tests that exercise persistence.
 * jsdom in this repo's Vitest config does not provide a working
 * window.localStorage, so modules that persist preferences (theme,
 * environment scope, language) get this in-memory Storage mock.
 */
import { beforeEach } from 'vitest';

const values = new Map<string, string>();

const storage: Storage = {
  getItem: (key: string) => values.get(key) ?? null,
  setItem: (key: string, value: string) => void values.set(key, value),
  removeItem: (key: string) => void values.delete(key),
  clear: () => values.clear(),
  key: (index: number) => [...values.keys()][index] ?? null,
  get length() {
    return values.size;
  },
};

export function installLocalStorageStub(): void {
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: storage,
  });
}

/** Install the stub once and clear it before each test. */
export function useLocalStorageStub(): void {
  installLocalStorageStub();
  beforeEach(() => values.clear());
}
