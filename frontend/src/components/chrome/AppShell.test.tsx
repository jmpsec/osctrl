import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppShell } from './AppShell';

vi.mock('@tanstack/react-router', () => ({
  useRouterState: () => ({ location: { pathname: '/_app/env/dev' } }),
}));

vi.mock('./SideNav', () => ({
  SideNav: ({ className }: { className?: string }) => <aside className={className}>Nav</aside>,
}));

vi.mock('./TopBar', () => ({
  TopBar: () => <header>Top</header>,
}));

vi.mock('./CommandPalette', () => ({
  CommandPalette: () => null,
}));

describe('AppShell', () => {
  beforeEach(() => {
    vi.stubGlobal('localStorage', {
      getItem: vi.fn(() => null),
      setItem: vi.fn(),
    });
  });

  it('makes main the fixed-height scroll container for sticky descendants', () => {
    const { container } = render(
      <AppShell username="alice">
        <section>Page content</section>
      </AppShell>,
    );

    const root = container.firstElementChild;
    expect(root).toHaveClass('h-screen');
    expect(root).toHaveClass('overflow-hidden');
    expect(root).not.toHaveClass('min-h-screen');

    const main = screen.getByRole('main');
    expect(main).toHaveClass('min-h-0');
    expect(main).toHaveClass('overflow-auto');
  });
});
