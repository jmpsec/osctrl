import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { StatCard } from './StatCard';

describe('StatCard', () => {
  it('renders the label', () => {
    render(<StatCard label="Active Nodes" value={42} />);
    expect(screen.getByText('Active Nodes')).toBeInTheDocument();
  });

  it('renders the value', () => {
    render(<StatCard label="Active Nodes" value={42} />);
    // toLocaleString may format 42 as "42" in all locales
    expect(screen.getByText('42')).toBeInTheDocument();
  });

  it('renders large numbers with locale formatting', () => {
    render(<StatCard label="Total Nodes" value={1234} />);
    // toLocaleString('en-US') renders 1234 as "1,234"
    // jsdom uses 'en-US' by default in the test environment
    const el = screen.getByText(/1.?234/);
    expect(el).toBeInTheDocument();
  });

  it('renders string values directly', () => {
    render(<StatCard label="Version" value="5.11.0" />);
    expect(screen.getByText('5.11.0')).toBeInTheDocument();
  });

  it('renders the trend chip when trend is provided', () => {
    render(<StatCard label="Active" value={10} trend="up" trendValue="2.3%" />);
    expect(screen.getByText('2.3%')).toBeInTheDocument();
    // Arrow for "up"
    expect(screen.getByText('↑')).toBeInTheDocument();
  });

  it('does not render the trend chip when trend is omitted', () => {
    render(<StatCard label="Active" value={10} />);
    expect(screen.queryByText('↑')).not.toBeInTheDocument();
    expect(screen.queryByText('↓')).not.toBeInTheDocument();
    expect(screen.queryByText('→')).not.toBeInTheDocument();
  });

  it('renders trend down arrow', () => {
    render(<StatCard label="Active" value={5} trend="down" trendValue="1%" />);
    expect(screen.getByText('↓')).toBeInTheDocument();
  });

  it('renders the sparkline svg when sparkline prop is provided', () => {
    const { container } = render(
      <StatCard label="Active" value={7} sparkline={[1, 2, 3, 4, 5, 6, 7]} />,
    );
    const svg = container.querySelector('svg[aria-hidden]');
    expect(svg).not.toBeNull();
  });

  it('does not render sparkline when sparkline prop is omitted', () => {
    const { container } = render(<StatCard label="Active" value={7} />);
    // The card itself has no aria-hidden svg (Logo is not used here)
    const sparklineSvg = container.querySelector('polyline');
    expect(sparklineSvg).toBeNull();
  });

  it('renders a custom visualization when provided', () => {
    render(
      <StatCard
        label="Queries"
        value={3}
        visualization={<div data-testid="custom-viz">custom</div>}
      />,
    );
    expect(screen.getByTestId('custom-viz')).toBeInTheDocument();
  });

  it('renders the sublabel when provided', () => {
    render(<StatCard label="Active" value={7} sublabel="last 24h" />);
    expect(screen.getByText('last 24h')).toBeInTheDocument();
  });

  it('applies the halo class via inline style', () => {
    const { container } = render(<StatCard label="Active" value={7} halo="warning" />);
    const card = container.firstElementChild as HTMLElement;
    expect(card.style.background).toContain('rgba(var(--warning-r), var(--warning-g), var(--warning-b)');
  });
});
