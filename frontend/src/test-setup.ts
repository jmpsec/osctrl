import '@testing-library/jest-dom/vitest'

// Initialize i18n for every component test. The instance reads
// navigator.languages at init; pinning to English here keeps snapshots
// and text-based queries deterministic regardless of the host locale.
import '$/i18n/i18n'
import { i18n } from '$/i18n/i18n'

void i18n.changeLanguage('en')

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
