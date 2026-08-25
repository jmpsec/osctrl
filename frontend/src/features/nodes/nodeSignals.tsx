import type { AdminTag, NodeHealth, NodeHealthStatus } from '$/api/types';
import { resolveTagIcon } from '$/components/forms/IconPicker';
import { StatusBadge } from '$/components/data/StatusBadge';
import { TagChip } from '$/components/data/TagChip';
import { MetadataBadge } from '$/components/data/MetadataBadge';

const HEALTH_LABELS: Record<NodeHealthStatus, string> = {
  healthy: 'Healthy',
  attention: 'Attention',
  at_risk: 'At risk',
  offline: 'Offline',
  unknown: 'Unknown',
};

const HEALTH_VARIANTS: Record<NodeHealthStatus, 'success' | 'warning' | 'danger' | 'dim'> = {
  healthy: 'success',
  attention: 'warning',
  at_risk: 'danger',
  offline: 'dim',
  unknown: 'dim',
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
    <StatusBadge
      variant={HEALTH_VARIANTS[status]}
      label={HEALTH_LABELS[status]}
      title={health?.reason}
    />
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
          <TagChip
            key={`${tag.id}-${tag.name}`}
            label={tag.name}
            color={tag.color}
            Icon={IconComp}
            title={tag.description || tag.name}
            className="max-w-[120px]"
          />
        );
      })}
      {overflow > 0 && <MetadataBadge className="tabular-nums">+{overflow}</MetadataBadge>}
    </div>
  );
}
