import { Grid as BklitGrid } from '$/components/charts/grid';
import { Line as BklitLine } from '$/components/charts/line';
import { LineChart as BklitLineChart } from '$/components/charts/line-chart';
import { ChartTooltip as BklitChartTooltip } from '$/components/charts/tooltip/chart-tooltip';
import { activeLocaleTag, formatLocaleNumber } from '$/i18n/useLocale';
import type { ActivitySeries, ChartCategory, ChartPalette } from './DashboardPage';

const CATEGORY_LABELS: Record<ChartCategory, string> = {
  status: 'Status logs',
  result: 'Query results',
  config: 'Config',
  query: 'Queries',
  error: 'Reported errors',
};

export interface ActivityLineChartProps {
  series: ActivitySeries;
  intervalLabel: '12h' | '24h' | '7d';
  palette: ChartPalette;
}

export default function ActivityLineChart({
  series,
  intervalLabel,
  palette,
}: ActivityLineChartProps) {
  const pointCount = Math.max(
    series.status.length,
    series.result.length,
    series.config.length,
    series.query.length,
    series.statusError.length,
  );
  const durationMs = intervalLabel === '7d'
    ? 7 * 24 * 60 * 60 * 1000
    : intervalLabel === '12h'
      ? 12 * 60 * 60 * 1000
      : 24 * 60 * 60 * 1000;
  const endTime = Date.now();
  const startTime = endTime - durationMs;
  const chartData = Array.from({ length: pointCount }, (_, index) => ({
    date: new Date(
      pointCount > 1
        ? startTime + (index / (pointCount - 1)) * durationMs
        : endTime,
    ),
    status: series.status[index] ?? 0,
    result: series.result[index] ?? 0,
    config: series.config[index] ?? 0,
    query: series.query[index] ?? 0,
    error: series.statusError[index] ?? 0,
  }));

  const startLabel = intervalLabel === '7d'
    ? '7 days ago'
    : intervalLabel === '12h'
      ? '12 hours ago'
      : '24 hours ago';

  return (
    <figure role="img" aria-label="Node activity by category, including reported errors" className="mt-2">
      <BklitLineChart
        data={chartData}
        aspectRatio="3 / 1"
        margin={{ top: 12, right: 8, bottom: 8, left: 8 }}
        animationDuration={760}
        animationEasing="cubic-bezier(0.32, 0.72, 0, 1)"
        yDomainTweenDuration={420}
        className="min-h-[180px]"
      >
        <BklitGrid
          horizontal
          numTicksRows={6}
          stroke="color-mix(in srgb, var(--text-3) 72%, transparent)"
          strokeDasharray="4 5"
          strokeOpacity={1}
          hideHorizontalEdgeLines
        />
        <BklitLine dataKey="status" stroke={palette.status} strokeWidth={2} fadeEdges={false} />
        <BklitLine dataKey="result" stroke={palette.result} strokeWidth={2} fadeEdges={false} />
        <BklitLine dataKey="config" stroke={palette.config} strokeWidth={2} fadeEdges={false} />
        <BklitLine dataKey="query" stroke={palette.query} strokeWidth={2} fadeEdges={false} />
        <BklitLine dataKey="error" stroke={palette.error} strokeWidth={2} fadeEdges={false} />
        <BklitChartTooltip
          showDatePill={false}
          dotVariant="ring"
          dotSize={4}
          indicatorColor="var(--chart-crosshair)"
          indicatorFadeEdges="both"
          matchCrosshair
          content={({ point }) => {
            const hoveredAt = point.date instanceof Date
              ? point.date
              : new Date(String(point.date));
            const hoveredLabel = intervalLabel === '7d'
              ? new Intl.DateTimeFormat(activeLocaleTag(), {
                  weekday: 'short',
                  month: 'short',
                  day: 'numeric',
                }).format(hoveredAt)
              : new Intl.DateTimeFormat(activeLocaleTag(), {
                  hour: 'numeric',
                  minute: '2-digit',
                }).format(hoveredAt);
            const rows = [
              { key: 'status' as const, value: Number(point.status ?? 0) },
              { key: 'result' as const, value: Number(point.result ?? 0) },
              { key: 'config' as const, value: Number(point.config ?? 0) },
              { key: 'query' as const, value: Number(point.query ?? 0) },
              { key: 'error' as const, value: Number(point.error ?? 0) },
            ];

            return (
              <div className="min-w-40 px-3 py-2.5">
                <div className="mb-2 text-xs font-medium text-[color:var(--chart-tooltip-muted)]">
                  {hoveredLabel}
                </div>
                <div className="space-y-1.5">
                  {rows.map(({ key, value }) => (
                    <div key={key} className="flex items-center justify-between gap-5 text-xs">
                      <span className="flex items-center gap-2 text-[color:var(--chart-tooltip-muted)]">
                        <span
                          className="h-0.5 w-3 rounded-full"
                          style={{ backgroundColor: palette[key] }}
                          aria-hidden
                        />
                        {CATEGORY_LABELS[key]}
                      </span>
                      <span className="font-semibold tabular-nums text-[color:var(--chart-tooltip-foreground)]">
                        {formatLocaleNumber(value)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            );
          }}
          panelStyle={{
            background: 'var(--chart-tooltip-background)',
            border: '1px solid var(--chart-tooltip-border)',
            boxShadow: 'var(--chart-tooltip-shadow)',
            backdropFilter: 'blur(18px) saturate(1.2)',
          }}
        />
      </BklitLineChart>
      <figcaption className="-mt-1 flex items-center justify-between px-2 text-xs font-medium tabular-nums text-[color:var(--text-3)]">
        <span>{startLabel}</span>
        <span>Now</span>
      </figcaption>
    </figure>
  );
}
