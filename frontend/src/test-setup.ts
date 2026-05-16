import '@testing-library/jest-dom/vitest'

// jsdom does not implement scrollTo — stub it so TanStack Router's scroll
// restoration code does not produce noisy "not implemented" console errors
// during component tests.
Object.defineProperty(window, 'scrollTo', {
  value: () => {},
  writable: true,
});
