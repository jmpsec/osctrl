import '@testing-library/jest-dom/vitest'

// jsdom does not implement scrollTo — stub it so TanStack Router's scroll
// restoration code does not produce noisy "not implemented" console errors
// during component tests.
Object.defineProperty(window, 'scrollTo', {
  value: () => {},
  writable: true,
});

// BKLiT's responsive charts use ResizeObserver through Visx. jsdom does not
// provide it, so component tests need a no-op observer implementation.
class TestResizeObserver implements ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, 'ResizeObserver', {
  value: TestResizeObserver,
  writable: true,
});
Object.defineProperty(window, 'ResizeObserver', {
  value: TestResizeObserver,
  writable: true,
});
