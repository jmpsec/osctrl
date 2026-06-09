/**
 * DashboardPage — cross-env overview of every environment's osquery activity.
 *
 * Data sources:
 *   GET /api/v1/stats                                  (polled every 30s)
 *   GET /api/v1/audit-logs?page_size=8                 (polled every 60s)
 *   GET /api/v1/nodes/{firstEnv}?page_size=5&sort=firstseen&dir=desc  (polled every 60s)
 *   GET /api/v1/stats/activity/{env}?interval=1d       (per env; summed for the
 *                                                       fleet-wide time-series
 *                                                       chart and KPI sparklines)
 */

import { useState } from 'react';
import { useQueries, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { getStats, getOsqueryVersionCounts, getEnvActivity } from '$/api/stats';
import type { PlatformCounts, ActivityBucket, ActivityInterval } from '$/api/stats';
import { listAuditLogs, LOG_TYPE, LOG_TYPE_LABELS } from '$/api/audit';
import { listNodes } from '$/api/nodes';
import { listQueries } from '$/api/queries';
import { listEnvironments } from '$/api/environments';
import { AuthError } from '$/api/client';
import { Skeleton } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { StatusPip } from '$/components/data/StatusPip';
import { cn } from '$/lib/cn';
import { formatRelative } from '$/lib/time';

// ---------------------------------------------------------------------------
// Aggregated 24h activity series, derived from the env-activity endpoint.
//
// `aggregateBuckets` collapses 96 15-min buckets into N evenly-spaced bins
// and sums per-category counts. The dashboard renders two views:
//   - 24 hourly bins for the main time-series chart (4 categories stacked)
//   - 12 two-hour bins for the per-KPI sparklines
//
// When the activity endpoint hasn't returned yet, an all-zero array is
// returned so the chart components render an empty frame rather than
// crashing or rendering a placeholder shape.
// ---------------------------------------------------------------------------
function aggregateBuckets(
  buckets: ActivityBucket[] | undefined,
  bins: number,
): { config: number[]; query: number[]; carve: number[]; enroll: number[] } {
  const out = {
    config: new Array<number>(bins).fill(0),
    query: new Array<number>(bins).fill(0),
    carve: new Array<number>(bins).fill(0),
    enroll: new Array<number>(bins).fill(0),
  };
  if (!buckets || buckets.length === 0) return out;
  const perBin = Math.max(1, Math.floor(buckets.length / bins));
  for (let i = 0; i < buckets.length; i++) {
    const binIdx = Math.min(bins - 1, Math.floor(i / perBin));
    out.config[binIdx] += buckets[i].config;
    out.query[binIdx] += buckets[i].query;
    out.carve[binIdx] += buckets[i].carve;
    out.enroll[binIdx] += buckets[i].enroll;
  }
  return out;
}

// ---------------------------------------------------------------------------
// LIVE badge — pulsing signal-teal pip with "LIVE" label.
// ---------------------------------------------------------------------------
function LiveBadge() {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5',
        'px-2 py-0.5 rounded-full',
        'text-[10px] font-mono-tabular font-medium uppercase tracking-[0.1em]',
        'border border-[color:var(--signal)]/30',
        'bg-[color:var(--signal)]/10',
        'text-[color:var(--signal-bright,var(--signal))]',
        'select-none',
      )}
      aria-label="Live — auto-refreshing every 30 seconds"
    >
      <span
        className="relative inline-block w-[7px] h-[7px] rounded-full bg-[color:var(--signal)] flex-shrink-0"
        aria-hidden
      >
        <span
          className="absolute inset-[-3px] rounded-full border border-[color:var(--signal)] motion-safe:animate-[osctrl-pulse_2s_ease-out_infinite]"
          aria-hidden
        />
      </span>
      LIVE
    </span>
  );
}

// ---------------------------------------------------------------------------
// Inline SVG sparkline — hand-drawn, no libs.
// ---------------------------------------------------------------------------
interface SparklineProps {
  points: number[];
  color?: string;
  width?: number;
  height?: number;
  fill?: boolean;
}
function InlineSparkline({
  points,
  color = 'var(--signal)',
  width = 96,
  height = 22,
  fill = true,
}: SparklineProps) {
  if (!points.length) return null;
  const minV = Math.min(...points);
  const maxV = Math.max(...points);
  const range = maxV - minV || 1;
  const pad = 2;
  const usableH = height - pad * 2;
  const stepX = (width - 1) / (points.length - 1);
  const coords = points.map((p, i) => ({
    x: i * stepX,
    y: pad + usableH - ((p - minV) / range) * usableH,
  }));
  const linePath = coords
    .map((c, i) => `${i === 0 ? 'M' : 'L'}${c.x.toFixed(1)},${c.y.toFixed(1)}`)
    .join(' ');
  const fillPath = `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${height} L0,${height} Z`;
  const gradId = `spk-${color.replace(/[^a-z0-9]/gi, '')}-${points.length}`;
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      aria-hidden
      className="overflow-visible"
      style={{ display: 'block' }}
    >
      {fill && (
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.18" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
      )}
      {fill && <path d={fillPath} fill={`url(#${gradId})`} />}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Time-series chart — 24h stacked area of audit-log activity, by category.
// Wired to the env-activity endpoint via aggregateBuckets.
// ---------------------------------------------------------------------------
function TimeSeriesChart({
  config,
  query,
  carve,
  enroll,
  intervalLabel,
}: {
  config: number[];
  query: number[];
  carve: number[];
  enroll: number[];
  intervalLabel: '24h' | '7d';
}) {
  const W = 600;
  const H = 200;
  const padL = 40;
  const padR = 10;
  const padT = 30;
  const padB = 30;
  const innerW = W - padL - padR;
  const innerH = H - padT - padB;
  const n = config.length;

  // Stack series bottom-to-top: enroll → carve → query → config. Compute the
  // running upper bound at each x so each layer's polygon traces the top of
  // the layer below it.
  const stack = config.map((_, i) => ({
    enroll: enroll[i],
    carve: enroll[i] + carve[i],
    query: enroll[i] + carve[i] + query[i],
    config: enroll[i] + carve[i] + query[i] + config[i],
  }));
  const maxV = Math.max(1, ...stack.map((s) => s.config));
  const stepX = n > 1 ? innerW / (n - 1) : innerW;

  const yFor = (v: number) => padT + (1 - v / maxV) * innerH;

  // Polygon between two series (used to draw a stacked layer).
  const layerPath = (top: number[], bottom: number[]) => {
    const fwd = top.map((v, i) => `${i === 0 ? 'M' : 'L'}${(padL + i * stepX).toFixed(1)},${yFor(v).toFixed(1)}`).join(' ');
    const back = bottom
      .map((v, i) => `L${(padL + (bottom.length - 1 - i) * stepX).toFixed(1)},${yFor(v).toFixed(1)}`)
      .reverse()
      .reverse() // keep order to traverse from right to left
      .join(' ');
    return `${fwd} ${back} Z`;
  };

  const enrollTop = stack.map((s) => s.enroll);
  const carveTop = stack.map((s) => s.carve);
  const queryTop = stack.map((s) => s.query);
  const configTop = stack.map((s) => s.config);
  const zero = stack.map(() => 0);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label="24-hour fleet activity by category">
      {/* Flat fills, not gradients. Stacked layers represent additive
          amounts; gradients made overlapping bands read muddy and
          inverted the visual hierarchy. Each layer now reads as a
          solid color band; the per-series top outline + gridlines
          carry depth. */}
      {/* gridlines */}
      <g stroke="var(--border)" strokeDasharray="2 4" strokeWidth="1">
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <line key={t} x1={padL} y1={padT + t * innerH} x2={W - padR} y2={padT + t * innerH} />
        ))}
      </g>
      {/* Y axis labels (max value at top) */}
      <g className="font-mono-tabular" fill="var(--text-3)" fontSize="9">
        {[1, 0.75, 0.5, 0.25, 0].map((t, i) => (
          <text key={t} x={padL - 6} y={padT + (i * innerH) / 4 + 3} textAnchor="end">
            {Math.round(maxV * t)}
          </text>
        ))}
      </g>
      {/* Stacked layers, bottom-to-top — flat fills.
          Config uses a chart-local violet instead of --success so it
          reads distinctly from --signal (queries). Both --signal and
          --success sit in the green-teal corner of the wheel and at
          flat 0.65 opacity they merged visually. The category color
          here is chart-only and does NOT propagate to other places
          where "config" might have semantic meaning. */}
      <path d={layerPath(enrollTop, zero)} fill="var(--info)" fillOpacity="0.65" />
      <path d={layerPath(carveTop, enrollTop)} fill="var(--warning)" fillOpacity="0.65" />
      <path d={layerPath(queryTop, carveTop)} fill="var(--signal)" fillOpacity="0.65" />
      <path d={layerPath(configTop, queryTop)} fill="#a78bfa" fillOpacity="0.65" />
      {/* Top-of-stack outline so the chart has a defined edge */}
      <path
        d={configTop.map((v, i) => `${i === 0 ? 'M' : 'L'}${(padL + i * stepX).toFixed(1)},${yFor(v).toFixed(1)}`).join(' ')}
        fill="none"
        stroke="#a78bfa"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      {/* X axis labels — 7 anchor points across the chart width, label
          format depends on the interval. */}
      <g className="font-mono-tabular" fill="var(--text-3)" fontSize="9">
        {(intervalLabel === '7d'
          ? ['-7d', '-6d', '-5d', '-4d', '-3d', '-2d', '-1d', 'now']
          : ['-24h', '-20h', '-16h', '-12h', '-8h', '-4h', 'now']
        ).map((lbl, i, arr) => {
          const x = padL + (i / (arr.length - 1)) * innerW;
          return (
            <text
              key={lbl}
              x={x}
              y={H - 8}
              textAnchor={i === 0 ? 'start' : i === arr.length - 1 ? 'end' : 'middle'}
            >
              {lbl}
            </text>
          );
        })}
      </g>
      {/* Legend */}
      <g className="font-mono-tabular" fontSize="11" fontWeight="500">
        <circle cx={padL + 4} cy={padT - 14} r="3" fill="#a78bfa" />
        <text x={padL + 12} y={padT - 10} fill="var(--text-2)">Config</text>
        <circle cx={padL + 70} cy={padT - 14} r="3" fill="var(--signal)" />
        <text x={padL + 78} y={padT - 10} fill="var(--text-2)">Query</text>
        <circle cx={padL + 130} cy={padT - 14} r="3" fill="var(--warning)" />
        <text x={padL + 138} y={padT - 10} fill="var(--text-2)">Carve</text>
        <circle cx={padL + 190} cy={padT - 14} r="3" fill="var(--info)" />
        <text x={padL + 198} y={padT - 10} fill="var(--text-2)">Enroll</text>
      </g>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Mid 4-KPI card — large stat, %-delta-vs-prior chip, mini sparkline.
// ---------------------------------------------------------------------------
type Halo = 'signal' | 'success' | 'warning' | 'danger' | 'info';
const haloRgba: Record<Halo, string> = {
  signal:  'rgba(var(--halo-r), var(--halo-g), var(--halo-b), 0.15)',
  success: 'rgba(var(--success-r), var(--success-g), var(--success-b), 0.14)',
  warning: 'rgba(var(--warning-r), var(--warning-g), var(--warning-b), 0.14)',
  danger:  'rgba(var(--danger-r), var(--danger-g), var(--danger-b), 0.14)',
  info:    'rgba(var(--info-r), var(--info-g), var(--info-b), 0.14)',
};
const sparkColor: Record<Halo, string> = {
  signal:  'var(--signal)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger:  'var(--danger)',
  info:    'var(--info)',
};
function computeDeltaPct(points: number[]): number | null {
  if (points.length < 2) return null;
  const first = points[0];
  const last = points[points.length - 1];
  if (first === 0) return last === 0 ? 0 : null;
  return Math.round(((last - first) / first) * 100);
}
function deltaTone(pct: number | null, polarity: 'up-good' | 'up-bad'): Halo {
  if (pct == null || pct === 0) return 'info';
  const isUp = pct > 0;
  if (polarity === 'up-good') return isUp ? 'success' : 'danger';
  return isUp ? 'danger' : 'success';
}

interface KpiCardProps {
  label: string;
  value: number;
  sparkline: number[];
  halo: Halo;
  /** "more is good" or "more is bad" for tinting the delta chip. */
  polarity?: 'up-good' | 'up-bad';
  /** Override the auto-computed delta label. */
  deltaLabel?: string;
}
function KpiCard({ label, value, sparkline, halo, polarity = 'up-good', deltaLabel }: KpiCardProps) {
  const pct = computeDeltaPct(sparkline);
  const tone = deltaTone(pct, polarity);
  const text =
    deltaLabel ??
    (pct == null
      ? 'no trend'
      : pct === 0
        ? 'steady'
        : `${pct > 0 ? '+' : ''}${pct}% vs prior`);
  const haloStyle: React.CSSProperties = {
    background: `radial-gradient(ellipse at top right, ${haloRgba[halo]} 0%, transparent 70%), var(--bg-1)`,
  };
  return (
    <div
      className={cn(
        'relative rounded-xl border border-[color:var(--border)]',
        'px-5 pt-4 pb-4 min-h-[136px]',
        'transition-shadow duration-[120ms] hover:shadow-[0_0_0_1px_var(--signal)]',
        'flex flex-col',
      )}
      style={haloStyle}
    >
      <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] select-none">
        {label}
      </div>
      <div className="font-display text-[36px] font-bold tabular-nums text-[color:var(--text-1)] leading-none mt-2">
        {value.toLocaleString()}
      </div>
      <div className="flex items-end justify-between mt-auto pt-3">
        <span
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
            'text-[10px] font-mono-tabular',
            tone === 'success' && 'bg-[color:var(--success)]/10 text-[color:var(--success)] border border-[color:var(--success)]/25',
            tone === 'danger'  && 'bg-[color:var(--danger)]/10 text-[color:var(--danger)] border border-[color:var(--danger)]/25',
            tone === 'info'    && 'bg-[color:var(--info)]/10 text-[color:var(--info)] border border-[color:var(--info)]/25',
          )}
        >
          <span aria-hidden>
            {pct == null || pct === 0 ? '→' : pct > 0 ? '↑' : '↓'}
          </span>
          {text}
        </span>
        <InlineSparkline points={sparkline} color={sparkColor[halo]} width={84} height={26} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hero KPI (large stat on the right of the time-series row).
// ---------------------------------------------------------------------------
function HeroKpi({
  label,
  description,
  value,
  unit,
  tone,
  toneText,
}: {
  label: string;
  description: string;
  value: number | string;
  unit?: string;
  tone: 'success' | 'info' | 'warning' | 'danger';
  toneText: string;
}) {
  const toneStyles: Record<string, string> = {
    success: 'bg-[color:var(--success)]/10 text-[color:var(--success)] border-[color:var(--success)]/25',
    info: 'bg-[color:var(--info)]/10 text-[color:var(--info)] border-[color:var(--info)]/25',
    warning: 'bg-[color:var(--warning)]/10 text-[color:var(--warning)] border-[color:var(--warning)]/25',
    danger: 'bg-[color:var(--danger)]/10 text-[color:var(--danger)] border-[color:var(--danger)]/25',
  };
  // Drive the corner halo from the card's semantic tone so each KPI
  // glows in its own color (queries-success → teal-green, carves-info →
  // blue, etc). Previously every HeroKpi had the same signal-teal halo
  // regardless of tone, which made warning/info cards "feel off"
  // because the badge color and the halo color disagreed.
  const toneHalo: Record<string, string> = {
    success: 'rgba(var(--success-r), var(--success-g), var(--success-b), 0.22)',
    info: 'rgba(var(--info-r), var(--info-g), var(--info-b), 0.22)',
    warning: 'rgba(var(--warning-r), var(--warning-g), var(--warning-b), 0.22)',
    danger: 'rgba(var(--danger-r), var(--danger-g), var(--danger-b), 0.22)',
  };
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)]',
        'px-5 py-4 flex flex-col h-full min-h-[120px]',
        'transition-shadow duration-[120ms] hover:shadow-[0_0_0_1px_var(--signal)]',
      )}
    >
      <div
        aria-hidden
        className="absolute -top-12 -right-12 w-32 h-32 rounded-full opacity-50"
        style={{ background: toneHalo[tone] }}
      />
      <div className="text-sm font-display font-semibold text-[color:var(--text-1)]">{label}</div>
      <div className="text-[11px] text-[color:var(--text-3)] mt-0.5">{description}</div>
      <div className="font-display tabular-nums mt-3 flex items-baseline gap-2 text-[color:var(--text-1)]" style={{ fontSize: 44, fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1 }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
        {unit && <span className="text-sm text-[color:var(--text-3)] font-normal">{unit}</span>}
      </div>
      <div className="mt-3">
        <span
          className={cn(
            'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
            'text-[10px] font-mono-tabular border',
            toneStyles[tone],
          )}
        >
          <span aria-hidden className="w-[6px] h-[6px] rounded-full bg-current" />
          {toneText}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Top platforms — horizontal mini stacked bar + legend rows.
// ---------------------------------------------------------------------------
const PLATFORM_LABEL: Record<keyof PlatformCounts, string> = {
  linux: 'Linux',
  darwin: 'macOS',
  windows: 'Windows',
  other: 'Other',
};
const PLATFORM_COLOR: Record<keyof PlatformCounts, string> = {
  linux: 'var(--plat-linux, var(--warning))',
  darwin: 'var(--plat-mac, var(--info))',
  windows: 'var(--plat-windows, var(--info))',
  other: 'var(--text-3)',
};
function TopPlatformsPanel({ counts, total }: { counts: PlatformCounts; total: number }) {
  const entries = (Object.keys(counts) as (keyof PlatformCounts)[])
    .map((k) => ({ key: k, count: counts[k] }))
    .sort((a, b) => b.count - a.count);
  return (
    <section
      aria-label="Hosts by platform"
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-5"
    >
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
          Hosts by platform
        </h2>
        <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums">
          {total.toLocaleString()} total
        </span>
      </div>
      {/* Stacked bar */}
      <div className="h-2 w-full rounded-full overflow-hidden bg-[color:var(--bg-3)] flex" aria-hidden>
        {entries.map(({ key, count }) => {
          const pct = total > 0 ? (count / total) * 100 : 0;
          if (pct === 0) return null;
          return (
            <div
              key={key}
              className="h-full"
              style={{ width: `${pct}%`, background: PLATFORM_COLOR[key] }}
              title={`${PLATFORM_LABEL[key]}: ${count}`}
            />
          );
        })}
      </div>
      {/* Legend */}
      <ul className="mt-3 grid grid-cols-2 gap-x-3 gap-y-1.5">
        {entries.map(({ key, count }) => {
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return (
            <li key={key} className="flex items-center gap-2 text-[11px]">
              <span
                aria-hidden
                className="w-2 h-2 rounded-full flex-shrink-0"
                style={{ background: PLATFORM_COLOR[key] }}
              />
              <span className="text-[color:var(--text-2)] flex-1 truncate">{PLATFORM_LABEL[key]}</span>
              <span className="font-mono-tabular text-[color:var(--text-1)] tabular-nums">{count}</span>
              <span className="font-mono-tabular text-[color:var(--text-3)] tabular-nums w-9 text-right">
                {pct}%
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Activity feed row
// ---------------------------------------------------------------------------
function avatarGradient(username: string): string {
  let h = 0;
  for (let i = 0; i < username.length; i++) h = (h * 31 + username.charCodeAt(i)) % 360;
  const h2 = (h + 40) % 360;
  return `linear-gradient(135deg, hsl(${h},60%,48%), hsl(${h2},70%,38%))`;
}
function initials(username: string): string {
  const parts = username.replace(/_/g, ' ').split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return username.slice(0, 2).toUpperCase();
}
function relativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}
function ActivityRow({
  username, service, logType, line, createdAt,
}: { username: string; service: string; logType: number; line: string; createdAt: string }) {
  const typeLabel = LOG_TYPE_LABELS[logType] ?? 'action';
  const isAuth = logType === 1 || logType === 2;
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
      <div
        className="flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-mono-tabular font-semibold text-white"
        style={{ background: avatarGradient(username) }}
        aria-hidden
      >
        {initials(username)}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[13px] leading-snug text-[color:var(--text-1)]">
          <span className="font-semibold">{username}</span>
          {' '}
          <span className="text-[color:var(--text-2)]">{isAuth ? typeLabel : `${typeLabel} via`}</span>
          {!isAuth && (
            <span className="font-mono-tabular text-[11px] text-[color:var(--signal)] ml-1 truncate">
              {service}
            </span>
          )}
        </div>
        {line && (
          <div className="text-[11px] text-[color:var(--text-3)] truncate mt-0.5 font-mono-tabular">
            {line.length > 64 ? `${line.slice(0, 64)}…` : line}
          </div>
        )}
      </div>
      <time
        className="flex-shrink-0 text-[10px] font-mono-tabular text-[color:var(--text-3)] mt-0.5 tabular-nums"
        dateTime={createdAt}
        title={new Date(createdAt).toLocaleString()}
      >
        {relativeTime(createdAt)}
      </time>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent enrollment row
// ---------------------------------------------------------------------------
function EnrollRow({
  hostname, platform, environment, lastSeen, isActive,
}: { hostname: string; platform: string; environment: string; lastSeen: string; isActive: boolean }) {
  return (
    <div className="flex items-center gap-3 py-2 border-b border-[color:var(--border)] last:border-0">
      <StatusPip variant={isActive ? 'success' : 'warning'} />
      <div className="flex-1 min-w-0">
        <div className="text-[13px] font-medium text-[color:var(--text-1)] truncate font-mono-tabular">
          {hostname || 'unknown'}
        </div>
        <div className="text-[10px] text-[color:var(--text-3)] mt-0.5 uppercase tracking-[0.08em] font-mono-tabular">
          {platform || '—'} · {environment}
        </div>
      </div>
      <time
        className="flex-shrink-0 text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums"
        dateTime={lastSeen}
        title={new Date(lastSeen).toLocaleString()}
      >
        {relativeTime(lastSeen)}
      </time>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeletons
// ---------------------------------------------------------------------------
function KpiSkeletonCard() {
  return (
    <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] px-5 pt-4 pb-4 min-h-[136px] flex flex-col gap-3">
      <Skeleton className="h-3 w-20" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-[22px] w-24 mt-auto" />
    </div>
  );
}
function ActivityRowSkeleton() {
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
      <Skeleton className="w-7 h-7 rounded-full flex-shrink-0" />
      <div className="flex-1 space-y-1.5">
        <Skeleton className="h-3 w-3/4" />
        <Skeleton className="h-2.5 w-1/2" />
      </div>
      <Skeleton className="h-2.5 w-10 flex-shrink-0 mt-0.5" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Environments table — replaces the EnvTileRich grid (denser, more data).
// Joins EnvStats with TLSEnvironment by uuid to surface enroll_expire.
// ---------------------------------------------------------------------------
interface EnvTableEnv {
  uuid: string;
  name: string;
  active: number;
  inactive: number;
  active_queries: number;
  active_carves: number;
  /** RFC3339 from TLSEnvironment.enroll_expire; undefined if env list missing. */
  enroll_expire?: string;
}

/** Tint for the enroll-expire cell. Past or <7d → danger, <30d → warning. */
function enrollExpireTone(iso?: string): 'danger' | 'warning' | 'normal' {
  if (!iso) return 'normal';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'normal';
  const diffMs = d.getTime() - Date.now();
  const DAY = 24 * 60 * 60 * 1000;
  if (diffMs < 7 * DAY) return 'danger';
  if (diffMs < 30 * DAY) return 'warning';
  return 'normal';
}

/** Compact relative time for a future timestamp ("in 4d", "in 12h", "expired"). */
function formatExpireRelative(iso?: string): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  const diffMs = d.getTime() - Date.now();
  if (diffMs <= 0) return 'expired';
  const HOUR = 60 * 60 * 1000;
  const DAY = 24 * HOUR;
  if (diffMs < HOUR) return `in ${Math.max(1, Math.floor(diffMs / (60 * 1000)))}m`;
  if (diffMs < DAY) return `in ${Math.floor(diffMs / HOUR)}h`;
  return `in ${Math.floor(diffMs / DAY)}d`;
}

function EnvTable({ envs }: { envs: EnvTableEnv[] }) {
  return (
    <div
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
      role="table"
      aria-label="Environments table"
    >
      <div
        role="row"
        className={cn(
          'grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-9',
          'items-center border-b border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] select-none',
        )}
      >
        <span>Environment</span>
        <span className="text-right">Active</span>
        <span className="text-right">Inactive</span>
        <span className="text-right">Queries</span>
        <span className="text-right">Carves</span>
        <span className="text-right">Enroll expires</span>
        <span className="text-right">&nbsp;</span>
      </div>
      {envs.map((env) => {
        const tone = enrollExpireTone(env.enroll_expire);
        const isHealthy = env.active > 0;
        const expireText = formatExpireRelative(env.enroll_expire);
        return (
          <div
            key={env.uuid}
            role="row"
            className={cn(
              'grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-11',
              'items-center border-b border-[color:var(--border)] last:border-0',
              'text-[13px] hover:bg-[color:var(--bg-2)]',
              'transition-colors duration-[120ms]',
            )}
          >
            <div className="flex items-center gap-2 min-w-0">
              <StatusPip variant={isHealthy ? 'success' : 'warning'} />
              <span className="font-display font-semibold text-[color:var(--text-1)] truncate">
                {env.name}
              </span>
            </div>
            <span className="font-mono-tabular tabular-nums text-[color:var(--text-1)] text-right">
              {env.active.toLocaleString()}
            </span>
            <span className="font-mono-tabular tabular-nums text-[color:var(--text-3)] text-right">
              {env.inactive.toLocaleString()}
            </span>
            <span className="font-mono-tabular tabular-nums text-[color:var(--text-1)] text-right">
              {env.active_queries.toLocaleString()}
            </span>
            <span className="font-mono-tabular tabular-nums text-[color:var(--text-1)] text-right">
              {env.active_carves.toLocaleString()}
            </span>
            <span
              className={cn(
                'font-mono-tabular tabular-nums text-right',
                tone === 'danger' && 'text-[color:var(--danger)]',
                tone === 'warning' && 'text-[color:var(--warning)]',
                tone === 'normal' && 'text-[color:var(--text-2)]',
              )}
              title={env.enroll_expire || undefined}
            >
              {expireText}
            </span>
            <Link
              to="/_app/env/$env/nodes"
              params={{ env: env.uuid }}
              className={cn(
                'text-[11px] font-medium text-[color:var(--signal)] hover:underline text-right',
                'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
                'focus-visible:outline-[color:var(--signal)]',
              )}
            >
              Open →
            </Link>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// osquery versions panel — bars + version + count, with optional UP-TO-DATE
// chip when the most-common version represents >80% of the fleet.
// ---------------------------------------------------------------------------
const VERSION_BAR_COLORS = [
  'var(--signal)',
  'var(--info)',
  'var(--success)',
  'var(--warning)',
] as const;

function OsqueryVersionsPanel({
  versions,
}: {
  versions: { version: string; count: number }[];
}) {
  const total = versions.reduce((s, v) => s + v.count, 0);
  const topPct = total > 0 ? (versions[0]?.count ?? 0) / total : 0;
  const showUpToDate = total > 0 && topPct > 0.8;
  return (
    <section
      aria-label="osquery agent versions"
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden flex flex-col"
    >
      <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
        <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)] flex items-center gap-2">
          osquery versions
          {showUpToDate && (
            <span
              className={cn(
                'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
                'text-[10px] font-mono-tabular uppercase tracking-[0.1em]',
                'border border-[color:var(--success)]/25 bg-[color:var(--success)]/10 text-[color:var(--success)]',
              )}
            >
              up-to-date
            </span>
          )}
        </h2>
        <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums">
          {total.toLocaleString()} hosts
        </span>
      </div>
      <div className="px-4 py-3 flex-1">
        {versions.length === 0 ? (
          <div className="py-6 text-center text-sm text-[color:var(--text-3)]">
            No agents reporting yet.
          </div>
        ) : (
          <ul className="flex flex-col gap-2">
            {versions.map((v, i) => (
              <li key={v.version || `unknown-${i}`} className="flex items-center gap-2.5">
                <span
                  aria-hidden
                  className="w-[2px] h-3.5 rounded-sm flex-shrink-0"
                  style={{ background: VERSION_BAR_COLORS[i % VERSION_BAR_COLORS.length] }}
                />
                <span className="font-mono-tabular text-[12px] text-[color:var(--text-1)] tabular-nums flex-1 truncate">
                  {v.version || 'unknown'}
                </span>
                <span className="font-mono-tabular text-[12px] text-[color:var(--text-3)] tabular-nums">
                  {v.count.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Active queries with live progress — flattened across envs, capped at 8.
// ---------------------------------------------------------------------------
interface ActiveQueryRow {
  name: string;
  envName: string;
  envUuid: string;
  expected: number;
  executions: number;
  errors: number;
}

function progressTone(row: ActiveQueryRow): 'success' | 'warning' | 'info' {
  if (row.errors > 0) return 'warning';
  if (row.expected > 0 && row.executions >= row.expected) return 'success';
  return 'info';
}

function ActiveQueryRowItem({
  row,
  elapsed,
}: {
  row: ActiveQueryRow;
  elapsed: string;
}) {
  const tone = progressTone(row);
  const pct =
    row.expected > 0
      ? Math.min(100, Math.round((row.executions / row.expected) * 100))
      : 0;
  const done = row.expected > 0 && row.executions >= row.expected;
  const barColor =
    tone === 'warning' ? 'var(--warning)' : tone === 'success' ? 'var(--success)' : 'var(--info)';
  return (
    <Link
      to="/_app/env/$env/queries/$name"
      params={{ env: row.envUuid, name: row.name }}
      className={cn(
        'grid grid-cols-12 gap-3 items-center px-4 h-11 border-b border-[color:var(--border)] last:border-0',
        'text-[13px] hover:bg-[color:var(--bg-2)] transition-colors duration-[120ms]',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px]',
        'focus-visible:outline-[color:var(--signal)]',
      )}
    >
      <div className="col-span-5 flex items-center gap-2.5 min-w-0">
        <StatusPip variant={tone} />
        <span className="font-mono-tabular font-medium text-[color:var(--text-1)] truncate">
          {row.name}
        </span>
      </div>
      <span
        className={cn(
          'col-span-2 inline-flex items-center justify-center px-1.5 py-0.5 rounded-full',
          'text-[10px] font-mono-tabular border border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-[color:var(--text-2)] truncate',
        )}
      >
        {row.envName}
      </span>
      <span className="col-span-2 font-mono-tabular text-[11px] tabular-nums text-[color:var(--text-3)] text-right">
        {row.executions.toLocaleString()} / {row.expected.toLocaleString()}
        {row.errors > 0 && (
          <>
            {' · '}
            <span className="text-[color:var(--warning)]">{row.errors} err</span>
          </>
        )}
      </span>
      <div
        className="col-span-2 h-1.5 rounded-full bg-[color:var(--bg-3)] overflow-hidden"
        role="meter"
        aria-label={`${pct}% complete`}
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{ width: `${pct}%`, background: barColor }}
        />
      </div>
      <span className="col-span-1 text-right text-[11px] font-mono-tabular text-[color:var(--text-3)] tabular-nums">
        {done ? 'done' : elapsed}
      </span>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Recently seen nodes — compact table below the activity feed.
// ---------------------------------------------------------------------------
interface RecentNodeRow {
  uuid: string;
  hostname: string;
  localname: string;
  platform: string;
  osquery_version: string;
  ip_address: string;
  last_seen: string;
  env: string;
}

function RecentlySeenNodesTable({
  nodes,
  envUuid,
}: {
  nodes: RecentNodeRow[];
  envUuid: string;
}) {
  return (
    <div
      className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
      role="table"
      aria-label="Recently seen nodes"
    >
      <div
        role="row"
        className={cn(
          'grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-9',
          'items-center border-b border-[color:var(--border)] bg-[color:var(--bg-2)]',
          'text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] select-none',
        )}
      >
        <span>Hostname</span>
        <span>Platform</span>
        <span>osquery</span>
        <span>IP</span>
        <span>Tags</span>
        <span className="text-right">Last seen</span>
      </div>
      {nodes.map((n) => {
        const display = n.hostname || n.localname || 'unknown';
        return (
          <div
            key={n.uuid}
            role="row"
            className={cn(
              'grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-11',
              'items-center border-b border-[color:var(--border)] last:border-0',
              'text-[13px] hover:bg-[color:var(--bg-2)] transition-colors duration-[120ms]',
            )}
          >
            <div className="flex flex-col gap-0.5 min-w-0">
              <Link
                to="/_app/env/$env/nodes/$uuid"
                params={{ env: envUuid, uuid: n.uuid }}
                className={cn(
                  'text-[color:var(--text-link)] hover:underline truncate',
                  'font-medium text-[13px] leading-tight',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1',
                  'focus-visible:outline-[color:var(--signal)] rounded',
                )}
              >
                {display}
              </Link>
              <span
                className="text-[10px] font-mono-tabular text-[color:var(--text-3)] leading-tight"
                title={n.uuid}
              >
                <span className="text-[color:var(--signal)]">{n.uuid.slice(0, 6)}</span>
                <span>…</span>
              </span>
            </div>
            <span className="text-[12px] text-[color:var(--text-2)] truncate uppercase tracking-[0.04em]">
              {n.platform || '—'}
            </span>
            <span className="font-mono-tabular text-[11px] text-[color:var(--text-3)] tabular-nums truncate">
              {n.osquery_version || '—'}
            </span>
            <span className="font-mono-tabular text-[11px] text-[color:var(--text-3)] tabular-nums truncate">
              {n.ip_address || '—'}
            </span>
            <span className="text-[11px] text-[color:var(--text-3)] truncate">—</span>
            <time
              className="text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums text-right"
              dateTime={n.last_seen}
              title={n.last_seen ? new Date(n.last_seen).toLocaleString() : ''}
            >
              {n.last_seen ? formatRelative(n.last_seen) : '—'}
            </time>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export function DashboardPage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 30_000,
    refetchIntervalInBackground: false,
  });

  const is401 = isError && error instanceof AuthError;

  const { data: auditData, isLoading: auditLoading } = useQuery({
    queryKey: ['dashboard-audit'],
    queryFn: () => listAuditLogs({ page_size: 8 }),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  const firstEnvUuid = data?.environments[0]?.uuid;
  const { data: recentNodes, isLoading: nodesLoading } = useQuery({
    queryKey: ['dashboard-recent-nodes', firstEnvUuid],
    queryFn: () =>
      listNodes({
        env: firstEnvUuid!,
        sort: 'firstseen',
        dir: 'desc',
        pageSize: 5,
      }),
    enabled: !!firstEnvUuid,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Recently seen nodes (NEW) — pulled from firstEnv, lastseen desc ────
  const { data: recentlySeenNodes, isLoading: recentlySeenLoading } = useQuery({
    queryKey: ['dashboard-recently-seen', firstEnvUuid],
    queryFn: () =>
      listNodes({
        env: firstEnvUuid!,
        sort: 'lastseen',
        dir: 'desc',
        pageSize: 8,
      }),
    enabled: !!firstEnvUuid,
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Failed enrolls (24h) — Node-typed audit lines starting with
  //    "failed enroll". Capped at 200 by the request; >= 200 → render "200+".
  const since24hIso = (() => {
    const d = new Date(Date.now() - 24 * 60 * 60 * 1000);
    return d.toISOString();
  })();
  const { data: failedEnrollData } = useQuery({
    queryKey: ['dashboard-failed-enrolls', since24hIso],
    queryFn: () =>
      listAuditLogs({ type: LOG_TYPE.Node, since: since24hIso, page_size: 200 }),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });
  const failedEnrollItems = failedEnrollData?.items ?? [];
  const failedEnrolls = failedEnrollItems.filter((it) =>
    (it.line ?? '').startsWith('failed enroll'),
  ).length;
  const failedEnrollOverflow = failedEnrollItems.length >= 200;

  // ── Environments list (NEW) — enriches EnvStats rows with enroll_expire.
  //    May 401 / 403 for non-super-admins; we silently fall back to no expire.
  const { data: envList } = useQuery({
    queryKey: ['dashboard-env-list'],
    queryFn: listEnvironments,
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });
  const envExpireByUuid = new Map<string, string>();
  for (const e of envList ?? []) envExpireByUuid.set(e.uuid, e.enroll_expire);

  // ── Activity series — one request per env, summed across envs for the
  //    fleet-wide time-series chart and the KPI-card sparklines. The user
  //    picks 24h vs 7d via the chart's tab row; the chart's KPI sparklines
  //    follow the same interval.
  const [activityInterval, setActivityInterval] = useState<ActivityInterval>('1d');
  const envUuids = (data?.environments ?? []).map((e) => e.uuid);
  const activityQueries = useQueries({
    queries: envUuids.map((uuid) => ({
      queryKey: ['dashboard-env-activity', uuid, activityInterval] as const,
      queryFn: () => getEnvActivity(uuid, activityInterval),
      refetchInterval: 30_000,
      refetchIntervalInBackground: false,
      retry: 1,
    })),
  });
  // Sum per-bucket counts across every env's response.
  const fleetActivity: ActivityBucket[] = (() => {
    const merged: Map<string, ActivityBucket> = new Map();
    for (const q of activityQueries) {
      for (const b of q.data ?? []) {
        const prev = merged.get(b.bucket_start);
        if (prev) {
          prev.config += b.config;
          prev.query += b.query;
          prev.carve += b.carve;
          prev.enroll += b.enroll;
        } else {
          merged.set(b.bucket_start, { ...b });
        }
      }
    }
    return [...merged.values()].sort((a, b) => a.bucket_start.localeCompare(b.bucket_start));
  })();
  // Bin counts depend on the picker. 24h → 24 hourly bins for the main
  // chart, 12 two-hour bins for the KPI sparklines. 7d → 28 six-hour bins
  // for the chart, 14 twelve-hour bins for the sparklines.
  const mainBins = activityInterval === '7d' ? 28 : 24;
  const sparkBins = activityInterval === '7d' ? 14 : 12;
  const fleet24 = aggregateBuckets(fleetActivity, mainBins);
  const fleet12 = aggregateBuckets(fleetActivity, sparkBins);

  const envTableRows: EnvTableEnv[] = (data?.environments ?? []).map((e) => ({
    uuid: e.uuid,
    name: e.name,
    active: e.active,
    inactive: e.inactive,
    active_queries: e.active_queries,
    active_carves: e.active_carves,
    enroll_expire: envExpireByUuid.get(e.uuid),
  }));

  // ── osquery agent versions (NEW) ──────────────────────────────────────
  const { data: versionCounts, isLoading: versionsLoading } = useQuery({
    queryKey: ['dashboard-osquery-versions'],
    queryFn: getOsqueryVersionCounts,
    refetchInterval: 5 * 60_000,
    refetchIntervalInBackground: false,
    retry: 1,
  });

  // ── Active queries with live progress (NEW) ───────────────────────────
  //   Parallel one-call-per-env; flattened and sliced to 8.
  const activeQueriesPerEnv = useQueries({
    queries: (data?.environments ?? []).map((e) => ({
      queryKey: ['dashboard-active-queries', e.uuid],
      queryFn: () =>
        listQueries({ env: e.uuid, target: 'active' as const, pageSize: 10 }),
      staleTime: 30_000,
      refetchInterval: 30_000,
      refetchIntervalInBackground: false,
      retry: 1,
    })),
  });
  const envsForActive = data?.environments ?? [];
  const activeQueriesFlat: (ActiveQueryRow & { _createdAt: string })[] =
    activeQueriesPerEnv
      .flatMap((r, i) => {
        const envMeta = envsForActive[i];
        if (!envMeta || !r.data) return [];
        return r.data.items.map((q) => ({
          name: q.name,
          envName: envMeta.name,
          envUuid: envMeta.uuid,
          expected: q.expected,
          executions: q.executions,
          errors: q.errors,
          _createdAt: q.created_at,
        }));
      })
      // Newest first so the top of the panel reflects the freshest work
      .sort(
        (a, b) =>
          new Date(b._createdAt).getTime() - new Date(a._createdAt).getTime(),
      )
      .slice(0, 8);
  const activeQueriesLoading =
    activeQueriesPerEnv.length > 0 &&
    activeQueriesPerEnv.some((r) => r.isLoading);

  const ACTIVE_THRESHOLD_MS = 24 * 60 * 60 * 1000;

  return (
    <div className="flex flex-col gap-5 px-6 py-6 max-w-[1400px] mx-auto w-full">

      {/* ── Page header ─────────────────────────────────────────────────── */}
      <header className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
            overview
          </div>
          <h1 className="font-display text-2xl font-bold text-[color:var(--text-1)] leading-tight">
            Dashboard
          </h1>
          <p className="text-sm text-[color:var(--text-2)] mt-1">
            Showing osquery activity within the last 24 hours
          </p>
        </div>
        <div className="flex items-center gap-2 mt-1 flex-shrink-0">
          <span
            className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full
              text-[10px] font-mono-tabular text-[color:var(--text-3)]
              border border-[color:var(--border)] bg-[color:var(--bg-1)]"
            title="Auto-refresh interval"
          >
            <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden>
              <path d="M21 12a9 9 0 11-3-6.7l3 2.7" />
            </svg>
            30s
          </span>
          <LiveBadge />
        </div>
      </header>

      {/* ── Top row: time-series chart (2 cols) + 2 hero KPIs stacked ───── */}
      <section
        aria-label="24-hour overview"
        aria-busy={isLoading}
        className="grid grid-cols-1 lg:grid-cols-3 gap-4"
      >
        <div className="lg:col-span-2 rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-[color:var(--border)]">
            <div>
              <div className="text-sm font-display font-semibold text-[color:var(--text-1)]">
                Time-series
              </div>
              <div className="text-[11px] font-mono-tabular text-[color:var(--text-3)] mt-0.5 tabular-nums">
                {activityInterval === '7d' ? 'Last 7 days' : 'Last 24 hours'} · audit-log activity
              </div>
            </div>
            <div className="flex items-center gap-1 text-[12px]" role="tablist" aria-label="Time range">
              <button
                type="button"
                role="tab"
                aria-selected={activityInterval === '7d'}
                onClick={() => setActivityInterval('7d')}
                className={cn(
                  'px-2 py-1 rounded transition-colors duration-[120ms]',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  activityInterval === '7d'
                    ? 'font-semibold text-[color:var(--signal)] border-b-2 border-[color:var(--signal)]'
                    : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
                )}
              >
                7 days
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activityInterval === '1d'}
                onClick={() => setActivityInterval('1d')}
                className={cn(
                  'px-2 py-1 rounded transition-colors duration-[120ms]',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
                  activityInterval === '1d'
                    ? 'font-semibold text-[color:var(--signal)] border-b-2 border-[color:var(--signal)]'
                    : 'text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
                )}
              >
                24 hours
              </button>
            </div>
          </div>
          <div className="p-5">
            <TimeSeriesChart
              config={fleet24.config}
              query={fleet24.query}
              carve={fleet24.carve}
              enroll={fleet24.enroll}
              intervalLabel={activityInterval === '7d' ? '7d' : '24h'}
            />
          </div>
        </div>

        <div className="grid grid-rows-2 gap-4">
          <HeroKpi
            label="Queries"
            description="queries ran in the last 24 hours"
            value={data?.total_active_queries ?? 0}
            tone="success"
            toneText={`${data?.total_active_queries ?? 0} active`}
          />
          <HeroKpi
            label="Forensic Carves"
            description="active carve operations in flight"
            value={data?.total_active_carves ?? 0}
            tone="info"
            toneText={`${data?.total_active_carves ?? 0} in flight`}
          />
        </div>
      </section>

      {/* ── Mid 4-KPI row ────────────────────────────────────────────────── */}
      <section aria-label="Environment KPIs" aria-busy={isLoading}>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {isLoading || (isError && !is401) ? (
            Array.from({ length: 4 }).map((_, i) => <KpiSkeletonCard key={i} />)
          ) : (
            <>
              <KpiCard
                label="Active Nodes"
                value={data?.active_nodes ?? 0}
                sparkline={fleet12.config}
                halo="success"
                polarity="up-good"
              />
              <KpiCard
                label="Inactive ≥ 24h"
                value={data?.inactive_nodes ?? 0}
                sparkline={fleet12.config}
                halo="warning"
                polarity="up-bad"
              />
              {/* Failed enrolls (24h) — danger-tinted when >0. */}
              <KpiCard
                label="Failed enrolls (24h)"
                value={failedEnrolls}
                sparkline={fleet12.enroll}
                halo={failedEnrolls > 0 ? 'danger' : 'success'}
                polarity="up-bad"
                deltaLabel={
                  failedEnrollOverflow
                    ? '200+ in 24h'
                    : failedEnrolls === 0
                      ? 'all clear'
                      : `${failedEnrolls} in 24h`
                }
              />
              <KpiCard
                label="Active Queries"
                value={data?.total_active_queries ?? 0}
                sparkline={fleet12.query}
                halo="signal"
                polarity="up-good"
              />
            </>
          )}
        </div>
      </section>

      {/* ── Active queries with live progress ────────────────────────────── */}
      <section aria-label="Active queries" aria-busy={activeQueriesLoading}>
        <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
          <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)]">
            <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)] flex items-center gap-2">
              Active queries
              {activeQueriesFlat.length > 0 && (
                <span
                  className={cn(
                    'inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full',
                    'text-[10px] font-mono-tabular uppercase tracking-[0.1em]',
                    'border border-[color:var(--signal)]/30 bg-[color:var(--signal)]/10',
                    'text-[color:var(--signal-bright,var(--signal))]',
                  )}
                >
                  <StatusPip variant="signal" live />
                  {activeQueriesFlat.length} live
                </span>
              )}
            </h2>
            {firstEnvUuid && (
              <Link
                to="/_app/env/$env/queries"
                params={{ env: firstEnvUuid }}
                className="text-[11px] font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
              >
                View all →
              </Link>
            )}
          </div>
          <div>
            {activeQueriesLoading && activeQueriesFlat.length === 0 ? (
              Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="grid grid-cols-12 gap-3 items-center px-4 h-11 border-b border-[color:var(--border)] last:border-0"
                >
                  <Skeleton className="col-span-5 h-3" />
                  <Skeleton className="col-span-2 h-4 rounded-full" />
                  <Skeleton className="col-span-2 h-3" />
                  <Skeleton className="col-span-2 h-1.5 rounded-full" />
                  <Skeleton className="col-span-1 h-3" />
                </div>
              ))
            ) : activeQueriesFlat.length === 0 ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No active queries.
              </div>
            ) : (
              activeQueriesFlat.map((row) => (
                <ActiveQueryRowItem
                  key={`${row.envUuid}-${row.name}`}
                  row={row}
                  elapsed={formatRelative(row._createdAt)}
                />
              ))
            )}
          </div>
        </div>
      </section>

      {/* ── Bottom-mid: Environments (2/3) + Top platforms (1/3) ─────────── */}
      <section aria-label="Environments" aria-busy={isLoading} className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Env table spans 2 columns at lg+ */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
              Environments
            </h2>
            {data && (
              <span className="text-xs text-[color:var(--text-3)] font-mono-tabular tabular-nums">
                {data.environments.length} env{data.environments.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>

          {isLoading ? (
            <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="grid grid-cols-[1.6fr_0.6fr_0.6fr_0.6fr_0.6fr_0.9fr_0.5fr] gap-3 px-4 h-11 items-center border-b border-[color:var(--border)] last:border-0"
                >
                  <Skeleton className="h-3 w-32" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-8 justify-self-end" />
                  <Skeleton className="h-3 w-16 justify-self-end" />
                  <Skeleton className="h-3 w-10 justify-self-end" />
                </div>
              ))}
            </div>
          ) : isError ? (
            <EmptyState
              icon={
                <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10 text-[color:var(--danger)]">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 8v4M12 16h.01" />
                </svg>
              }
              title={is401 ? 'Session expired. Please log in again.' : 'Failed to load stats.'}
              description={is401 ? undefined : 'Check the API connection and try again.'}
              action={
                !is401 ? (
                  <button
                    onClick={() => void refetch()}
                    className="text-sm font-medium text-[color:var(--signal)] hover:underline"
                  >
                    Retry
                  </button>
                ) : undefined
              }
            />
          ) : data?.environments.length === 0 ? (
            <EmptyState
              icon={
                <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10">
                  <path d="M3 12h6v9H3zM15 3h6v9h-6zM3 3h6v6H3zM15 15h6v6h-6z" />
                </svg>
              }
              title="No environments configured."
              description="Contact your administrator to set up an environment."
            />
          ) : (
            <EnvTable envs={envTableRows} />
          )}
        </div>

        {/* Top platforms — right column */}
        <div>
          {isLoading || isError ? (
            <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-5 min-h-[160px]">
              <Skeleton className="h-4 w-32 mb-3" />
              <Skeleton className="h-2 w-full rounded-full mb-3" />
              <div className="space-y-1.5">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-3 w-full" />
                ))}
              </div>
            </div>
          ) : data ? (
            <TopPlatformsPanel counts={data.platform_counts} total={data.total_nodes} />
          ) : null}
        </div>
      </section>

      {/* ── osquery versions panel ───────────────────────────────────────── */}
      <section aria-label="osquery agent versions">
        {versionsLoading ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-5 min-h-[160px]">
            <Skeleton className="h-4 w-32 mb-3" />
            <div className="space-y-1.5">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-3 w-full" />
              ))}
            </div>
          </div>
        ) : (
          <OsqueryVersionsPanel versions={versionCounts ?? []} />
        )}
      </section>

      {/* ── Activity feed + Recent enrollments ──────────────────────────── */}
      <section aria-label="Recent activity and enrollments" className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Activity feed — 2/3 width on md+ */}
        <div className="md:col-span-2 rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
            <span className="text-[13px] font-semibold font-display text-[color:var(--text-1)]">
              Recent activity
            </span>
            <Link
              to="/_app/audit"
              className="text-[11px] font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
            >
              View all →
            </Link>
          </div>
          <div className="px-4 flex-1">
            {auditLoading ? (
              Array.from({ length: 5 }).map((_, i) => <ActivityRowSkeleton key={i} />)
            ) : !auditData?.items.length ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No audit events yet.
              </div>
            ) : (
              auditData.items.map((entry) => (
                <ActivityRow
                  key={entry.id}
                  username={entry.username}
                  service={entry.service}
                  logType={entry.log_type}
                  line={entry.line}
                  createdAt={entry.created_at}
                />
              ))
            )}
          </div>
        </div>

        {/* Recent enrollments — 1/3 */}
        <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 h-11 border-b border-[color:var(--border)] flex-shrink-0">
            <span className="text-[13px] font-semibold font-display text-[color:var(--text-1)]">
              Recent enrollments
            </span>
            {firstEnvUuid && (
              <Link
                to="/_app/env/$env/nodes"
                params={{ env: firstEnvUuid }}
                className="text-[11px] font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
              >
                View all →
              </Link>
            )}
          </div>
          <div className="px-4 flex-1">
            {nodesLoading || (!firstEnvUuid && isLoading) ? (
              Array.from({ length: 3 }).map((_, i) => (
                <div key={i} className="flex items-center gap-3 py-2.5 border-b border-[color:var(--border)] last:border-0">
                  <Skeleton className="w-2 h-2 rounded-full flex-shrink-0" />
                  <div className="flex-1 space-y-1.5">
                    <Skeleton className="h-3 w-3/4" />
                    <Skeleton className="h-2 w-1/2" />
                  </div>
                  <Skeleton className="h-2.5 w-8 flex-shrink-0" />
                </div>
              ))
            ) : !firstEnvUuid ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No environment selected.
              </div>
            ) : !recentNodes?.items.length ? (
              <div className="py-8 text-center text-sm text-[color:var(--text-3)]">
                No nodes enrolled yet.
              </div>
            ) : (
              recentNodes.items.map((node) => {
                const isActive =
                  Date.now() - new Date(node.last_seen).getTime() < ACTIVE_THRESHOLD_MS;
                return (
                  <EnrollRow
                    key={node.uuid}
                    hostname={node.hostname || node.localname}
                    platform={node.platform}
                    environment={node.environment}
                    lastSeen={node.last_seen}
                    isActive={isActive}
                  />
                );
              })
            )}
          </div>
        </div>
      </section>

      {/* ── Recently seen nodes ─────────────────────────────────────────── */}
      <section aria-label="Recently seen nodes" aria-busy={recentlySeenLoading}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-display font-semibold text-[color:var(--text-1)]">
            Recently seen nodes
          </h2>
          {firstEnvUuid && (
            <Link
              to="/_app/env/$env/nodes"
              params={{ env: firstEnvUuid }}
              className="text-[11px] font-medium text-[color:var(--signal)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]"
            >
              View all →
            </Link>
          )}
        </div>
        {!firstEnvUuid && !isLoading ? (
          <EmptyState
            icon={
              <svg aria-hidden viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-10 h-10">
                <path d="M3 12h6v9H3zM15 3h6v9h-6zM3 3h6v6H3zM15 15h6v6h-6z" />
              </svg>
            }
            title="No environment available."
            description="Recently seen nodes appear once you have at least one environment."
          />
        ) : recentlySeenLoading || isLoading ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden">
            {Array.from({ length: 5 }).map((_, i) => (
              <div
                key={i}
                className="grid grid-cols-[1.4fr_0.8fr_0.7fr_0.9fr_0.7fr_0.5fr] gap-3 px-4 h-11 items-center border-b border-[color:var(--border)] last:border-0"
              >
                <Skeleton className="h-3 w-36" />
                <Skeleton className="h-3 w-16" />
                <Skeleton className="h-3 w-12" />
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-3 w-8" />
                <Skeleton className="h-3 w-12 justify-self-end" />
              </div>
            ))}
          </div>
        ) : !recentlySeenNodes?.items.length ? (
          <div className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] py-8 text-center text-sm text-[color:var(--text-3)]">
            No nodes have reported in yet.
          </div>
        ) : (
          <RecentlySeenNodesTable
            envUuid={firstEnvUuid!}
            nodes={recentlySeenNodes.items.map((n) => ({
              uuid: n.uuid,
              hostname: n.hostname,
              localname: n.localname,
              platform: n.platform,
              osquery_version: n.osquery_version,
              ip_address: n.ip_address,
              last_seen: n.last_seen,
              env: n.environment,
            }))}
          />
        )}
      </section>

    </div>
  );
}
