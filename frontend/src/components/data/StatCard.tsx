/**
 * StatCard — KPI card with halo backdrop, optional sparkline, optional trend chip.
 * Matches the brand guide §08 "Status & data viz" KPI card conventions.
 */

import { cn } from '$/lib/cn';
import { Sparkline } from './Sparkline';

export type HaloVariant = 'signal' | 'success' | 'warning' | 'danger' | 'info';
export type TrendDirection = 'up' | 'down' | 'flat';

const sparklineColors: Record<HaloVariant, string> = {
  signal:  'var(--signal)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger:  'var(--danger)',
  info:    'var(--info)',
};

const trendColors: Record<TrendDirection, string> = {
  up:   'text-[color:var(--success)]',
  down: 'text-[color:var(--danger)]',
  flat: 'text-[color:var(--text-3)]',
};

const trendArrows: Record<TrendDirection, string> = {
  up:   '↑',
  down: '↓',
  flat: '→',
};

interface StatCardProps {
  label: string;
  value: number | string;
  /** Optional sub-label rendered below the value. */
  sublabel?: string;
  trend?: TrendDirection;
  trendValue?: string;
  sparkline?: number[];
  halo?: HaloVariant;
  className?: string;
  /** Custom visualization to render in place of the sparkline area. */
  visualization?: React.ReactNode;
}

export function StatCard({
  label,
  value,
  sublabel,
  trend,
  trendValue,
  sparkline,
  halo = 'signal',
  className,
  visualization,
}: StatCardProps) {
  return (
    <div
      className={cn(
        'relative flex flex-col',
        'rounded-lg border border-[color:var(--border)] bg-[color:var(--bg-1)]',
        'px-4 py-3.5',
        'min-h-[120px]',
        'transition-colors duration-[100ms]',
        'hover:border-[color:var(--border-strong)]',
        className,
      )}
    >
      {/* Label */}
      <div className="text-xs font-medium text-[color:var(--text-2)] select-none mb-1">
        {label}
      </div>

      {/* Value */}
      <div className="font-display text-2xl font-semibold tabular-nums text-[color:var(--text-1)] leading-none">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>

      {/* Sub-label */}
      {sublabel && (
        <div className="text-xs text-[color:var(--text-3)] mt-1">{sublabel}</div>
      )}

      {/* Trend chip */}
      {trend && (
        <div
          className={cn(
            'inline-flex items-center gap-1 text-xs font-medium mt-2',
            trendColors[trend],
          )}
          aria-label={`Trend: ${trend}${trendValue ? ` ${trendValue}` : ''}`}
        >
          <span aria-hidden>{trendArrows[trend]}</span>
          {trendValue && <span>{trendValue}</span>}
        </div>
      )}

      {/* Sparkline or custom visualization */}
      {(sparkline || visualization) && (
        <div className="mt-auto pt-3">
          {visualization ?? (
            sparkline && (
              <Sparkline
                points={sparkline}
                color={sparklineColors[halo]}
                width={100}
                height={22}
              />
            )
          )}
        </div>
      )}
    </div>
  );
}
