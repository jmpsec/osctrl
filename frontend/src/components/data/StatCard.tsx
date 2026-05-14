/**
 * StatCard — KPI card with halo backdrop, optional sparkline, optional trend chip.
 * Matches the brand guide §08 "Status & data viz" KPI card conventions.
 */

import { cn } from '$/lib/cn';
import { Sparkline } from './Sparkline';

export type HaloVariant = 'signal' | 'success' | 'warning' | 'danger' | 'info';
export type TrendDirection = 'up' | 'down' | 'flat';

// CSS variable references for each semantic color pair (RGB components for halo).
const haloVars: Record<HaloVariant, string> = {
  signal:  'rgba(var(--halo-r), var(--halo-g), var(--halo-b), 0.15)',
  success: 'rgba(var(--success-r), var(--success-g), var(--success-b), 0.14)',
  warning: 'rgba(var(--warning-r), var(--warning-g), var(--warning-b), 0.14)',
  danger:  'rgba(var(--danger-r), var(--danger-g), var(--danger-b), 0.14)',
  info:    'rgba(var(--info-r), var(--info-g), var(--info-b), 0.14)',
};

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
  const halosStyle: React.CSSProperties = {
    background: `radial-gradient(ellipse at top left, ${haloVars[halo]} 0%, transparent 70%), var(--bg-1)`,
  };

  return (
    <div
      className={cn(
        'relative flex flex-col justify-between',
        'rounded-lg border border-[color:var(--border)]',
        'px-5 pt-4 pb-4',
        'min-h-[130px]',
        'transition-shadow duration-[120ms]',
        'hover:shadow-[0_0_0_1px_var(--signal)]',
        className,
      )}
      style={halosStyle}
    >
      {/* Label */}
      <div className="text-[10px] font-mono-tabular uppercase tracking-[0.12em] text-[color:var(--text-3)] select-none mb-1">
        {label}
      </div>

      {/* Value */}
      <div className="font-display text-3xl font-bold tabular-nums text-[color:var(--text-1)] leading-none">
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
        <div className="mt-3">
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
