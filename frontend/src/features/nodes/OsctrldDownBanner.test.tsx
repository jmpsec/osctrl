import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { OsctrldDownBanner } from './OsctrldDownBanner';
import type { NodeFlags } from '$/api/types';

type Osctrld = NonNullable<NodeFlags['osctrld']>;

const DOWN = '2026-10-20T08:00:00Z';
const REPORTED = '2026-10-20T08:05:00Z';
const loc = (iso: string) => new Date(iso).toLocaleString();

const make = (extra: Partial<Osctrld> = {}): Osctrld => ({
  last_fetched_at: '2026-10-18T10:00:00Z',
  apply_result: 'applied',
  apply_error: '',
  apply_at: null,
  rejected_current: false,
  ...extra,
});

describe('OsctrldDownBanner', () => {
  it('shows down since, report time, flags stage and apply error as plain text', () => {
    render(
      <OsctrldDownBanner
        osctrld={make({
          osquery_running: false,
          down_since: DOWN,
          reported_at: REPORTED,
          flags_stage: 'last_known_good',
          apply_error: '<b>bad flag</b>',
        })}
      />,
    );
    const banner = screen.getByTestId('osquery-down-banner');
    expect(banner).toHaveAttribute('role', 'alert');
    expect(banner).toHaveTextContent(`osquery is down since ${loc(DOWN)}`);
    expect(banner).toHaveTextContent(`(reported by osctrld ${loc(REPORTED)})`);
    expect(banner).toHaveTextContent('osctrld rolled back to the last known good flags');
    expect(banner).toHaveTextContent('<b>bad flag</b>');
    expect(banner.querySelector('b')).toBeNull();
  });

  it('describes the other stages and omits since when down_since is missing', () => {
    render(
      <OsctrldDownBanner
        osctrld={make({ osquery_running: false, reported_at: REPORTED, flags_stage: 'exhausted', extensions_stage: 'restored' })}
      />,
    );
    const banner = screen.getByTestId('osquery-down-banner');
    expect(banner).toHaveTextContent('osquery is down');
    expect(banner).not.toHaveTextContent('since');
    expect(banner).toHaveTextContent('no fallback kept osquery running');
    expect(banner).toHaveTextContent('osctrld restored the previous extensions');
  });

  it('notes a stale report and still shows the banner', () => {
    render(<OsctrldDownBanner osctrld={make({ osquery_running: false, down_since: DOWN, reported_at: REPORTED, report_stale: true })} />);
    expect(screen.getByTestId('osquery-down-banner')).toHaveTextContent(`Last report ${loc(REPORTED)}, it may be stale.`);
  });

  it('renders nothing when osquery is running, unreported, or there is no osctrld', () => {
    const { container, rerender } = render(<OsctrldDownBanner osctrld={make({ osquery_running: true, reported_at: REPORTED })} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<OsctrldDownBanner osctrld={make()} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<OsctrldDownBanner osctrld={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
