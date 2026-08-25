import type { ReactNode } from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { ActivitySeries, ChartPalette } from './DashboardPage';
import ActivityLineChart from './ActivityLineChart';

// This test owns the dashboard-to-BKLiT adapter contract. The chart library's
// responsive SVG layout is intentionally not exercised in jsdom; the mocks
// expose the exact data and line props that our component sends to BKLiT.
vi.mock('$/components/charts/grid', () => ({
  Grid: ({
    horizontal,
    numTicksRows,
    stroke,
    strokeDasharray,
    strokeOpacity,
  }: {
    horizontal?: boolean;
    numTicksRows?: number;
    stroke?: string;
    strokeDasharray?: string;
    strokeOpacity?: number;
  }) => (
    <span
      data-testid="activity-grid"
      data-horizontal={horizontal}
      data-row-ticks={numTicksRows}
      data-stroke={stroke}
      data-stroke-dasharray={strokeDasharray}
      data-stroke-opacity={strokeOpacity}
    />
  ),
}));

vi.mock('$/components/charts/line', () => ({
  Line: ({ dataKey, stroke }: { dataKey: string; stroke: string }) => (
    <span data-testid={`series-${dataKey}`} data-stroke={stroke} />
  ),
}));

vi.mock('$/components/charts/line-chart', () => ({
  LineChart: ({
    data,
    children,
  }: {
    data: Array<Record<string, unknown>>;
    children: ReactNode;
  }) => (
    <div data-testid="line-chart" data-chart={JSON.stringify(data)}>
      {children}
    </div>
  ),
}));

vi.mock('$/components/charts/tooltip/chart-tooltip', () => ({
  ChartTooltip: () => null,
}));

const palette: ChartPalette = {
  status: '#67c0ff',
  result: '#2bc4be',
  config: '#a78bfa',
  query: '#4ade80',
  error: '#ff4d4f',
};

describe('ActivityLineChart', () => {
  it('renders readable horizontal dashed guides', () => {
    const series: ActivitySeries = {
      status: [4, 5, 6, 7],
      result: [1, 2, 3, 4],
      config: [2, 2, 2, 2],
      query: [0, 1, 0, 1],
      statusError: [0, 2, 0, 5],
      total: [7, 10, 11, 14],
    };

    render(
      <ActivityLineChart
        series={series}
        intervalLabel="24h"
        palette={palette}
      />,
    );

    expect(screen.getByTestId('activity-grid')).toHaveAttribute(
      'data-horizontal',
      'true',
    );
    expect(screen.getByTestId('activity-grid')).toHaveAttribute(
      'data-row-ticks',
      '6',
    );
    expect(screen.getByTestId('activity-grid')).toHaveAttribute(
      'data-stroke-dasharray',
      '4 5',
    );
    expect(screen.getByTestId('activity-grid')).toHaveAttribute(
      'data-stroke',
      'color-mix(in srgb, var(--text-3) 72%, transparent)',
    );
    expect(screen.getByTestId('activity-grid')).toHaveAttribute(
      'data-stroke-opacity',
      '1',
    );
  });

  it('maps reported errors into the BKLiT data and error line', () => {
    const series: ActivitySeries = {
      status: [4, 5, 6, 7],
      result: [1, 2, 3, 4],
      config: [2, 2, 2, 2],
      query: [0, 1, 0, 1],
      statusError: [0, 2, 0, 5],
      total: [7, 10, 11, 14],
    };

    render(
      <ActivityLineChart
        series={series}
        intervalLabel="24h"
        palette={palette}
      />,
    );

    const encodedData = screen.getByTestId('line-chart').getAttribute('data-chart');
    expect(encodedData).not.toBeNull();
    const chartData = JSON.parse(encodedData!) as Array<{ error: number }>;
    expect(chartData.map((point) => point.error)).toEqual([0, 2, 0, 5]);

    expect(screen.getAllByTestId(/^series-/)).toHaveLength(5);
    expect(screen.getByTestId('series-error')).toHaveAttribute(
      'data-stroke',
      '#ff4d4f',
    );
  });
});
