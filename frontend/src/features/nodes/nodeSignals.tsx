import type { AdminTag, NodeHealth, NodeHealthStatus } from '$/api/types';
import { cn } from '$/lib/cn';
import { resolveTagIcon } from '$/components/forms/IconPicker';

const HEALTH_LABELS: Record<NodeHealthStatus, string> = {
  healthy: 'healthy',
  attention: 'attention',
  at_risk: 'at risk',
  offline: 'offline',
  unknown: 'unknown',
};

const HEALTH_CLASSES: Record<NodeHealthStatus, string> = {
  healthy: 'border-[color:var(--success)]/25 bg-[color:var(--success)]/10 text-[color:var(--success)]',
  attention: 'border-[color:var(--warning)]/25 bg-[color:var(--warning)]/10 text-[color:var(--warning)]',
  at_risk: 'border-[color:var(--danger)]/25 bg-[color:var(--danger)]/10 text-[color:var(--danger)]',
  offline: 'border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
  unknown: 'border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--text-3)]',
};

function normalizeHealthStatus(status?: string): NodeHealthStatus {
  if (status === 'healthy' || status === 'attention' || status === 'at_risk' || status === 'offline') {
    return status;
  }
  return 'unknown';
}

export function HealthBadge({ health }: { health?: NodeHealth }) {
  const status = normalizeHealthStatus(health?.status);
  return (
    <span
      title={health?.reason}
      className={cn(
        'inline-flex w-fit items-center rounded-full border px-2 py-0.5',
        'text-[10px] font-mono-tabular uppercase tracking-[0.08em]',
        HEALTH_CLASSES[status],
      )}
    >
      {HEALTH_LABELS[status]}
    </span>
  );
}

export function TagChips({
  tags,
  max = 3,
  empty = '—',
}: {
  tags?: AdminTag[];
  max?: number;
  empty?: string;
}) {
  const list = tags ?? [];
  if (list.length === 0) {
    return <span className="text-[color:var(--text-3)]">{empty}</span>;
  }
  const visible = list.slice(0, max);
  const overflow = list.length - visible.length;
  return (
    <div className="flex flex-wrap items-center gap-1">
      {visible.map((tag) => {
        const IconComp = resolveTagIcon(tag.icon);
        return (
          <span
            key={`${tag.id}-${tag.name}`}
            className="inline-flex max-w-[120px] items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10.5px] font-mono-tabular leading-tight"
            style={{
              borderColor: `${tag.color || '#64748b'}55`,
              backgroundColor: `${tag.color || '#64748b'}18`,
              color: tag.color || 'var(--text-2)',
            }}
            title={tag.description || tag.name}
          >
            {IconComp && <IconComp className="w-2.5 h-2.5 flex-shrink-0" aria-hidden />}
            <span className="truncate">{tag.name}</span>
          </span>
        );
      })}
      {overflow > 0 && (
        <span className="text-[10.5px] font-mono-tabular text-[color:var(--text-3)]">
          +{overflow}
        </span>
      )}
    </div>
  );
}
