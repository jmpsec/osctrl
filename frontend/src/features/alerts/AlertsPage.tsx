import { useState, useMemo, useEffect, type ReactNode } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  listAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
  listAlertChannels,
  listAlertChannelTypes,
  createAlertChannel,
  updateAlertChannel,
  deleteAlertChannel,
  listAlertHistory,
  applyAlerts,
  type AlertRule,
  type AlertChannel,
  type AlertChannelTypeSpec,
  type AlertFieldSpec,
  type AlertHistoryEntry,
  type AlertRuleRequest,
  type AlertChannelRequest,
} from '$/api/alerts';
import { listEnvironments } from '$/api/environments';
import { getFeatures } from '$/api/features';
import { getServiceCommand } from '$/api/service-config';
import { AuthError } from '$/api/client';
import { formatRelative } from '$/lib/time';
import { SkeletonRow } from '$/components/data/Skeleton';
import { EmptyState } from '$/components/data/EmptyState';
import { ModalShell } from '$/components/feedback/ModalShell';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';
import { StatusBadge } from '$/components/data/StatusBadge';

const GLOBAL_ENV_ID = 0;
// Sentinel for the env selector: no env filter at all, so the list shows
// every environment's rules. GLOBAL_ENV_ID is a real filter (env 0 rows),
// not "everything" — a rule created from a node's page lives in that
// node's environment and was invisible under it.
const ALL_ENVS = -1;

/** Rule sources the form offers, with human descriptions. */
const RULE_SOURCES = [
  { value: 'result_log', label: 'Result logs', help: 'Scheduled-query result rows (columns and snapshot rows).' },
  { value: 'status_log', label: 'Status logs', help: 'osquery daemon status messages, filtered by severity.' },
  { value: 'query_log', label: 'Distributed query results', help: 'On-demand query answers submitted by nodes.' },
  { value: 'node_inactive', label: 'Node inactive', help: 'Node last_seen crosses the inactive threshold. No pattern needed.' },
  { value: 'node_recovered', label: 'Node recovered', help: 'A previously inactive node is seen again. No pattern needed.' },
] as const;

/** Sources that match patterns (vs. node-state sources). */
const PATTERN_SOURCES = new Set(['result_log', 'status_log', 'query_log']);

type Tab = 'rules' | 'channels' | 'history';

type RuleModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; rule: AlertRule };

type ChannelModalMode =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; channel: AlertChannel };

function sourceLabel(source: string): string {
  return RULE_SOURCES.find((s) => s.value === source)?.label ?? source;
}

/**
 * Alerts admin page.
 *
 * Three tabs: Rules (what to watch), Channels (where notifications go),
 * History (what was dispatched). Rules and channels are env-scoped with a
 * global fallback (env 0), matching log sinks. Edits queue locally in the
 * database; "Apply changes" hot-reloads osctrl-tls without a restart.
 *
 * Visual/structural conventions mirror LogSinksPage: sticky header,
 * SkeletonRow loading, EmptyState for empty/error, ModalShell dialogs,
 * CSS-var tokens only.
 */
export function AlertsPage() {
  usePageTitle('Alerts');
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [tab, setTab] = useState<Tab>('rules');
  const [selectedEnv, setSelectedEnv] = useState<number>(ALL_ENVS);
  const [ruleModal, setRuleModal] = useState<RuleModalMode>({ kind: 'closed' });
  const [channelModal, setChannelModal] = useState<ChannelModalMode>({ kind: 'closed' });
  const [applyErr, setApplyErr] = useState<string | null>(null);
  const [applyFlash, setApplyFlash] = useState(false);
  const [reloading, setReloading] = useState(false);

  const { data: features } = useQuery({
    queryKey: ['features'],
    queryFn: () => getFeatures(),
    staleTime: 5 * 60_000,
  });
  const alertsDisabled = features?.alerts === false;

  const { data: envs } = useQuery({
    queryKey: ['environments'],
    queryFn: () => listEnvironments(),
    staleTime: 60_000,
  });

  const rulesQuery = useQuery({
    queryKey: ['alert-rules', selectedEnv],
    queryFn: () => listAlertRules(selectedEnv === ALL_ENVS ? undefined : { env: selectedEnv }),
    enabled: !!features?.alerts,
    staleTime: 30_000,
  });

  const channelsQuery = useQuery({
    queryKey: ['alert-channels', selectedEnv],
    queryFn: () => listAlertChannels(selectedEnv === ALL_ENVS ? undefined : { env: selectedEnv }),
    enabled: !!features?.alerts,
    staleTime: 30_000,
  });

  const { data: channelTypes } = useQuery({
    queryKey: ['alert-channel-types'],
    queryFn: () => listAlertChannelTypes(),
    staleTime: 60_000,
    enabled: !!features?.alerts,
  });

  const historyQuery = useQuery({
    queryKey: ['alert-history'],
    queryFn: () => listAlertHistory(100),
    enabled: !!features?.alerts && tab === 'history',
    staleTime: 15_000,
  });

  const invalidate = (keys: string[]) => {
    for (const key of keys) void qc.invalidateQueries({ queryKey: [key] });
  };

  const deleteRuleMutation = useMutation({
    mutationFn: (id: number) => deleteAlertRule(id),
    onSuccess: () => invalidate(['alert-rules']),
    onError: (e) => {
      if (e instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  const deleteChannelMutation = useMutation({
    mutationFn: (id: number) => deleteAlertChannel(id),
    onSuccess: () => invalidate(['alert-channels']),
    onError: (e) => {
      if (e instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setApplyErr(e instanceof Error ? e.message : 'Delete failed');
    },
  });

  const applyMutation = useMutation({
    mutationFn: () => applyAlerts(),
    onSuccess: (resp) => {
      setApplyErr(null);
      if (!resp.command) {
        setReloading(false);
        setApplyFlash(true);
        setTimeout(() => setApplyFlash(false), 3000);
        return;
      }
      setReloading(true);
      const poll = setInterval(() => {
        getServiceCommand(resp.command!.command_id)
          .then((cmd) => {
            if (cmd.status !== 'pending') {
              clearInterval(poll);
              setReloading(false);
              setApplyFlash(true);
              setTimeout(() => setApplyFlash(false), 3000);
            }
          })
          .catch(() => {
            clearInterval(poll);
            setReloading(false);
          });
      }, 1500);
    },
    onError: (e: unknown) => {
      setApplyErr(e instanceof Error ? e.message : String(e));
    },
  });

  // Memoized data BEFORE any early return (React rules of hooks —
  // early returns must not skip hook calls).
  const rules = useMemo(
    () => [...(rulesQuery.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
    [rulesQuery.data],
  );
  const channels = useMemo(
    () => [...(channelsQuery.data ?? [])].sort((a, b) => a.name.localeCompare(b.name)),
    [channelsQuery.data],
  );
  const history = historyQuery.data ?? [];
  const envName = (id: number) =>
    id === GLOBAL_ENV_ID ? 'Global' : (envs?.find((e) => e.id === id)?.name ?? `env ${id}`);

  // Early returns AFTER all hooks (React rules of hooks).
  if (
    (rulesQuery.isError && rulesQuery.error instanceof AuthError) ||
    (channelsQuery.isError && channelsQuery.error instanceof AuthError)
  ) {
    void navigate({ to: '/login' });
    return null;
  }

  if (alertsDisabled) {
    return <FeatureDisabledShell />;
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Sticky header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Alerts
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Rules match ingested logs and node state; channels deliver the
          notifications. Global rules apply to every environment.
        </p>
        <div className="ml-auto flex items-center gap-2">
          <Button
            type="button"
            onClick={() =>
              tab === 'channels'
                ? setChannelModal({ kind: 'create' })
                : setRuleModal({ kind: 'create' })
            }
          >
            {tab === 'channels' ? 'New channel' : 'New rule'}
          </Button>
          <button
            type="button"
            disabled={reloading}
            title="Hot-reload osctrl-tls with the current rule and channel rows"
            onClick={() => {
              setApplyErr(null);
              applyMutation.mutate();
            }}
            className={cn(
              'px-3 py-1 text-xs font-medium rounded transition-colors',
              reloading
                ? 'bg-[color:var(--bg-3)] text-[color:var(--text-3)]'
                : 'bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)] hover:bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.2)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {reloading
              ? 'Reloading…'
              : applyFlash
                ? 'Reload triggered ✓'
                : 'Apply changes'}
          </button>
        </div>
      </div>

      {applyErr && (
        <div
          role="alert"
          className="px-4 py-2 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] border-b border-[color:var(--danger)]/30"
        >
          {applyErr}
        </div>
      )}

      {/* Tabs + env selector */}
      <div className="flex items-center gap-4 px-4 py-2 border-b border-[color:var(--border)] text-xs">
        <div role="tablist" aria-label="Alert sections" className="flex items-center gap-1">
          {(['rules', 'channels', 'history'] as const).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              type="button"
              onClick={() => setTab(t)}
              className={cn(
                'px-3 py-1.5 rounded-md font-medium capitalize transition-colors',
                tab === t
                  ? 'bg-[color:var(--bg-3)] text-[color:var(--text-1)]'
                  : 'text-[color:var(--text-3)] hover:text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)]',
              )}
            >
              {t}
            </button>
          ))}
        </div>
        {tab !== 'history' && (
          <div className="ml-auto flex items-center gap-2">
            <label htmlFor="alerts-env" className="text-[color:var(--text-2)] font-semibold">
              Environment
            </label>
            <select
              id="alerts-env"
              value={selectedEnv}
              onChange={(e) => setSelectedEnv(Number(e.target.value))}
              aria-label="Select environment whose alerts to show"
              className={cn(
                'px-2 py-1 rounded tabular-nums',
                'bg-[color:var(--bg-3)] border border-[color:var(--border)] text-[color:var(--text-1)]',
                'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
              )}
            >
              <option value={ALL_ENVS}>All environments</option>
              <option value={GLOBAL_ENV_ID}>Global rules only</option>
              {envs?.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto min-h-0">
        {tab === 'rules' && (
          <RulesTable
            rules={rules}
            loading={rulesQuery.isLoading}
            envName={envName}
            channels={channels}
            onEdit={(rule) => setRuleModal({ kind: 'edit', rule })}
            onDelete={(id) => deleteRuleMutation.mutate(id)}
          />
        )}
        {tab === 'channels' && (
          <ChannelsTable
            channels={channels}
            types={channelTypes ?? []}
            loading={channelsQuery.isLoading}
            envName={envName}
            onEdit={(channel) => setChannelModal({ kind: 'edit', channel })}
            onDelete={(id) => deleteChannelMutation.mutate(id)}
          />
        )}
        {tab === 'history' && (
          <HistoryTable
            entries={history}
            loading={historyQuery.isLoading}
          />
        )}
      </div>

      {/* Modals */}
      {ruleModal.kind !== 'closed' && (
        <RuleEditorModal
          mode={ruleModal}
          envs={envs ?? []}
          channels={channels}
          onClose={() => setRuleModal({ kind: 'closed' })}
          onSaved={() => {
            setRuleModal({ kind: 'closed' });
            invalidate(['alert-rules']);
          }}
        />
      )}
      {channelModal.kind !== 'closed' && (
        <ChannelEditorModal
          mode={channelModal}
          types={channelTypes ?? []}
          onClose={() => setChannelModal({ kind: 'closed' })}
          onSaved={() => {
            setChannelModal({ kind: 'closed' });
            invalidate(['alert-channels']);
          }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Disabled shell
// ---------------------------------------------------------------------------

function FeatureDisabledShell() {
  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">
          Alerts
        </h1>
        <p className="text-xs text-[color:var(--text-3)]">
          Super-admin view. Alert rules, channels, and dispatch history.
        </p>
      </div>
      <div className="flex-1 overflow-auto min-h-0">
        <EmptyState
          icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.7 21a2 2 0 01-3.4 0" />
            </svg>
          }
          title="Alerting is disabled"
          description={
            'osctrl-api runs with service.alertsEnabled = false, so the alerting subsystem is fully inert: no alert tables, no rule evaluation in osctrl-tls, and no /api/v1/alerts endpoints. Set alertsEnabled: true and restart osctrl-api and osctrl-tls to manage alerts here.'
          }
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

// Grid templates are shared between each table's header and its rows so the
// two can never drift out of alignment.
const RULES_GRID =
  'grid grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.2fr)_80px_minmax(0,1fr)_120px] items-center gap-3 px-4';
const CHANNELS_GRID =
  'grid grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)_minmax(0,2fr)_120px] items-center gap-3 px-4';

// Column titles, in the same style as the <th> rows on the other admin
// pages. The last column holds the status badge and row actions, so it is
// right-aligned to match.
function TableHeader({ grid, columns }: { grid: string; columns: string[] }) {
  return (
    <div
      className={cn(
        grid,
        'sticky top-0 z-10 py-2 bg-[color:var(--bg-2)]',
        'text-xs font-medium uppercase tracking-wide text-[color:var(--text-2)]',
      )}
    >
      {columns.map((label, i) => (
        <div key={label || i} className={cn('truncate', i === columns.length - 1 && 'text-right')}>
          {label}
        </div>
      ))}
    </div>
  );
}

function RulesTable({
  rules,
  loading,
  envName,
  channels,
  onEdit,
  onDelete,
}: {
  rules: AlertRule[];
  loading: boolean;
  envName: (id: number) => string;
  channels: AlertChannel[];
  onEdit: (rule: AlertRule) => void;
  onDelete: (id: number) => void;
}) {
  if (loading) {
    return (
      <div className="divide-y divide-[color:var(--border)]">
        {Array.from({ length: 4 }).map((_, i) => (
          <SkeletonRow key={i} cells={7} />
        ))}
      </div>
    );
  }
  if (rules.length === 0) {
    return (
      <EmptyState
        icon={<RuleIcon />}
        title="No alert rules"
        description="Rules match ingested logs and node state. Create one to start alerting — global rules apply to every environment."
      />
    );
  }
  const channelName = (id: number) =>
    channels.find((c) => c.id === id)?.name ?? `#${id}`;
  return (
    <div className="divide-y divide-[color:var(--border)]">
      <TableHeader
        grid={RULES_GRID}
        columns={['Rule', 'Source', 'Match', 'Pattern', 'Cooldown', 'Channels', 'Status']}
      />
      {rules.map((rule) => (
        <div
          key={rule.id}
          className={cn(RULES_GRID, 'py-2.5 text-sm hover:bg-[color:var(--bg-2)] transition-colors')}
        >
          <div className="min-w-0">
            <div className="font-medium text-[color:var(--text-1)] truncate">{rule.name}</div>
            <div className="text-xs text-[color:var(--text-3)] truncate">
              {envName(rule.environment_id)}
            </div>
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">
            {sourceLabel(rule.source)}
            {rule.node_uuid && (
              <span
                title={`Scoped to node ${rule.node_uuid}`}
                className="ml-1.5 inline-block max-w-[110px] truncate align-middle rounded bg-[color:var(--bg-3)] border border-[color:var(--border)] px-1 py-px font-mono text-[10px] text-[color:var(--text-3)]"
              >
                {rule.node_uuid}
              </span>
            )}
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">
            {PATTERN_SOURCES.has(rule.source)
              ? `${rule.match_type}${rule.match_field ? ` · ${rule.match_field}` : ' · any field'}`
              : '—'}
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate font-mono">
            {PATTERN_SOURCES.has(rule.source) ? rule.match_value : '—'}
          </div>
          <div className="text-xs text-[color:var(--text-3)] tabular-nums">
            {rule.cooldown_minutes > 0 ? `${rule.cooldown_minutes}m` : 'default'}
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">
            {rule.channel_ids.length > 0
              ? rule.channel_ids.map(channelName).join(', ')
              : <span className="text-[color:var(--text-3)]">none</span>}
          </div>
          <div className="flex items-center justify-end gap-2">
            <StatusBadge variant={rule.enabled ? 'success' : 'dim'} label={rule.enabled ? 'Enabled' : 'Disabled'} />
            <button
              type="button"
              onClick={() => onEdit(rule)}
              className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--text-1)] px-1.5 py-0.5 rounded hover:bg-[color:var(--bg-3)]"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onDelete(rule.id)}
              className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--danger)] px-1.5 py-0.5 rounded hover:bg-[color:var(--bg-3)]"
            >
              Delete
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function ChannelsTable({
  channels,
  types,
  loading,
  envName,
  onEdit,
  onDelete,
}: {
  channels: AlertChannel[];
  types: AlertChannelTypeSpec[];
  loading: boolean;
  envName: (id: number) => string;
  onEdit: (channel: AlertChannel) => void;
  onDelete: (id: number) => void;
}) {
  if (loading) {
    return (
      <div className="divide-y divide-[color:var(--border)]">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonRow key={i} cells={4} />
        ))}
      </div>
    );
  }
  if (channels.length === 0) {
    return (
      <EmptyState
        icon={<BellIcon />}
        title="No alert channels"
        description="Channels deliver notifications — a webhook, an email relay. Rules reference channels by name."
      />
    );
  }
  const description = (type: string) =>
    types.find((t) => t.type === type)?.description ?? '';
  return (
    <div className="divide-y divide-[color:var(--border)]">
      <TableHeader
        grid={CHANNELS_GRID}
        columns={['Channel', 'Type', 'Description', 'Status']}
      />
      {channels.map((channel) => (
        <div
          key={channel.id}
          className={cn(CHANNELS_GRID, 'py-2.5 text-sm hover:bg-[color:var(--bg-2)] transition-colors')}
        >
          <div className="min-w-0">
            <div className="font-medium text-[color:var(--text-1)] truncate">{channel.name}</div>
            <div className="text-xs text-[color:var(--text-3)] truncate">
              {envName(channel.environment_id)}
            </div>
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">{channel.type}</div>
          <div className="text-xs text-[color:var(--text-3)] truncate">
            {description(channel.type)}
          </div>
          <div className="flex items-center justify-end gap-2">
            <StatusBadge variant={channel.enabled ? 'success' : 'dim'} label={channel.enabled ? 'Enabled' : 'Disabled'} />
            <button
              type="button"
              onClick={() => onEdit(channel)}
              className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--text-1)] px-1.5 py-0.5 rounded hover:bg-[color:var(--bg-3)]"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={() => onDelete(channel.id)}
              className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--danger)] px-1.5 py-0.5 rounded hover:bg-[color:var(--bg-3)]"
            >
              Delete
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function HistoryTable({
  entries,
  loading,
}: {
  entries: AlertHistoryEntry[];
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="divide-y divide-[color:var(--border)]">
        {Array.from({ length: 6 }).map((_, i) => (
          <SkeletonRow key={i} cells={5} />
        ))}
      </div>
    );
  }
  if (entries.length === 0) {
    return (
      <EmptyState
        icon={<BellIcon />}
        title="No alerts dispatched yet"
        description="History records every notification the system sent, per channel. It fills in as rules match."
      />
    );
  }
  return (
    <div className="divide-y divide-[color:var(--border)]">
      {entries.map((entry) => (
        <div
          key={entry.id}
          className="grid grid-cols-[110px_minmax(0,1fr)_minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,2fr)] items-center gap-3 px-4 py-2.5 text-sm"
        >
          <div className="text-xs text-[color:var(--text-3)] tabular-nums">
            {formatRelative(entry.created_at)}
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">
            {entry.rule_name}
          </div>
          <div className="text-xs text-[color:var(--text-2)] truncate">
            {entry.channel_name || '—'}
          </div>
          <div className="text-xs text-[color:var(--text-3)] truncate font-mono">
            {entry.node_uuid || entry.entity}
          </div>
          <div className="text-xs text-[color:var(--text-3)] truncate" title={entry.detail}>
            {entry.detail}
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rule editor modal
// ---------------------------------------------------------------------------

function RuleEditorModal({
  mode,
  envs,
  channels,
  onClose,
  onSaved,
}: {
  mode: RuleModalMode;
  envs: { id: number; name: string }[];
  channels: AlertChannel[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const existing = mode.kind === 'edit' ? mode.rule : null;
  const [name, setName] = useState(existing?.name ?? '');
  const [envID, setEnvID] = useState<number>(existing?.environment_id ?? GLOBAL_ENV_ID);
  const [source, setSource] = useState(existing?.source ?? 'result_log');
  const [matchType, setMatchType] = useState(existing?.match_type ?? 'substring');
  const [matchField, setMatchField] = useState(existing?.match_field ?? '');
  const [matchValue, setMatchValue] = useState(existing?.match_value ?? '');
  const [statusSeverity, setStatusSeverity] = useState(existing?.status_severity || 'any');
  const [cooldown, setCooldown] = useState(existing?.cooldown_minutes ?? 0);
  const [channelIDs, setChannelIDs] = useState<number[]>(existing?.channel_ids ?? []);
  const nodeScope = existing?.node_uuid ?? '';
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [err, setErr] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (body: AlertRuleRequest) =>
      existing ? updateAlertRule(existing.id, body) : createAlertRule(body),
    onSuccess: onSaved,
    onError: (e) => {
      if (e instanceof AuthError) return;
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const inputClass = cn(
    'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
    'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
  );
  const needsPattern = PATTERN_SOURCES.has(source);
  const sourceHelp = RULE_SOURCES.find((s) => s.value === source)?.help;

  const submit = () => {
    if (!name.trim()) {
      setErr('Name is required');
      return;
    }
    if (needsPattern && !matchValue.trim()) {
      setErr('Match value is required for pattern sources');
      return;
    }
    mutation.mutate({
      name: name.trim(),
      environment_id: envID,
      source,
      node_uuid: nodeScope || undefined,
      match_type: needsPattern ? matchType : 'substring',
      match_field: needsPattern ? matchField : '',
      match_value: needsPattern ? matchValue : '',
      status_severity: source === 'status_log' ? statusSeverity : 'any',
      cooldown_minutes: cooldown,
      channel_ids: channelIDs,
      enabled,
    });
  };

  return (
    <ModalShell
      title={existing ? `Edit ${existing.name}` : 'New alert rule'}
      titleId="alert-rule-editor-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-4"
      >
        <div>
          <label htmlFor="rule-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Name
          </label>
          <input
            id="rule-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. sudoers-modified"
            className={inputClass}
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="rule-env" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Environment
            </label>
            <select
              id="rule-env"
              value={envID}
              onChange={(e) => setEnvID(Number(e.target.value))}
              className={inputClass}
            >
              <option value={GLOBAL_ENV_ID}>Global (all environments)</option>
              {envs.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="rule-source" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Source
            </label>
            <select
              id="rule-source"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className={inputClass}
            >
              {RULE_SOURCES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
            {sourceHelp && (
              <p className="mt-1 text-xs text-[color:var(--text-3)]">{sourceHelp}</p>
            )}
          </div>
        </div>

        {needsPattern && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="rule-match-type" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
                  Match type
                </label>
                <select
                  id="rule-match-type"
                  value={matchType}
                  onChange={(e) => setMatchType(e.target.value)}
                  className={inputClass}
                >
                  <option value="substring">Substring (case-insensitive)</option>
                  <option value="regex">Regex</option>
                </select>
              </div>
              <div>
                <label htmlFor="rule-match-field" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
                  Field <span className="font-normal text-[color:var(--text-3)]">(empty = any)</span>
                </label>
                <input
                  id="rule-match-field"
                  type="text"
                  value={matchField}
                  onChange={(e) => setMatchField(e.target.value)}
                  placeholder="e.g. path, username, message"
                  className={inputClass}
                />
              </div>
            </div>
            <div>
              <label htmlFor="rule-match-value" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
                Pattern
              </label>
              <input
                id="rule-match-value"
                type="text"
                value={matchValue}
                onChange={(e) => setMatchValue(e.target.value)}
                placeholder={matchType === 'regex' ? '^/etc/(shadow|sudoers)$' : '/etc/sudoers'}
                className={cn(inputClass, 'font-mono')}
              />
            </div>
          </>
        )}

        {source === 'status_log' && (
          <div>
            <label htmlFor="rule-severity" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Minimum severity
            </label>
            <select
              id="rule-severity"
              value={statusSeverity}
              onChange={(e) => setStatusSeverity(e.target.value)}
              className={inputClass}
            >
              <option value="any">Any</option>
              <option value="warning">Warning and above</option>
              <option value="error">Error only</option>
            </select>
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="rule-cooldown" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
              Cooldown (minutes)
            </label>
            <input
              id="rule-cooldown"
              type="number"
              min={0}
              value={cooldown}
              onChange={(e) => setCooldown(Number(e.target.value))}
              className={inputClass}
            />
            <p className="mt-1 text-xs text-[color:var(--text-3)]">
              Suppresses repeat alerts for the same match within the window. 0 uses the default (15m).
            </p>
          </div>
          <fieldset className="flex items-end gap-2 pb-2">
            <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
              />
              <span className="tabular-nums">enabled</span>
            </label>
          </fieldset>
        </div>

        <div>
          <span className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Channels
          </span>
          {channels.length === 0 ? (
            <p className="text-xs text-[color:var(--text-3)]">
              No channels yet — the rule will match but nothing is sent. Create a channel in the Channels tab.
            </p>
          ) : (
            <div className="space-y-1">
              {channels.map((c) => (
                <label key={c.id} className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
                  <input
                    type="checkbox"
                    checked={channelIDs.includes(c.id)}
                    onChange={(e) => {
                      setChannelIDs((prev) =>
                        e.target.checked ? [...prev, c.id] : prev.filter((id) => id !== c.id),
                      );
                    }}
                    className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
                  />
                  <span className="tabular-nums">{c.name}</span>
                  <span className="text-[color:var(--text-3)]">({c.type})</span>
                </label>
              ))}
            </div>
          )}
        </div>

        {err && (
          <p role="alert" className="text-xs text-[color:var(--danger)]">
            {err}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving…' : existing ? 'Save changes' : 'Create rule'}
          </Button>
        </div>
      </form>
    </ModalShell>
  );
}

// ---------------------------------------------------------------------------
// Channel editor modal — registry-driven dynamic form
// ---------------------------------------------------------------------------

function ChannelEditorModal({
  mode,
  types,
  onClose,
  onSaved,
}: {
  mode: ChannelModalMode;
  types: AlertChannelTypeSpec[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const existing = mode.kind === 'edit' ? mode.channel : null;
  const [name, setName] = useState(existing?.name ?? '');
  const [type, setType] = useState(existing?.type ?? 'webhook');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [config, setConfig] = useState<Record<string, unknown>>(
    (existing?.config as Record<string, unknown>) ?? {},
  );
  const [err, setErr] = useState<string | null>(null);

  // Reset the config object when the type changes during creation.
  useEffect(() => {
    if (mode.kind === 'create' && !existing) {
      setConfig(applyDefaults(types.find((t) => t.type === type)));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const spec = types.find((t) => t.type === type);

  const mutation = useMutation({
    mutationFn: (body: AlertChannelRequest) =>
      existing ? updateAlertChannel(existing.id, body) : createAlertChannel(body),
    onSuccess: onSaved,
    onError: (e) => {
      if (e instanceof AuthError) return;
      setErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const inputClass = cn(
    'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
    'bg-[color:var(--bg-3)] text-[color:var(--text-1)] tabular-nums',
    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
  );

  const submit = () => {
    if (!name.trim()) {
      setErr('Name is required');
      return;
    }
    mutation.mutate({
      name: name.trim(),
      environment_id: GLOBAL_ENV_ID,
      type,
      enabled,
      config,
    });
  };

  return (
    <ModalShell
      title={existing ? `Edit ${existing.name}` : 'New alert channel'}
      titleId="alert-channel-editor-title"
      onClose={onClose}
      bodyClassName="max-h-[70vh] overflow-y-auto"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
        className="space-y-4"
      >
        <div>
          <label htmlFor="channel-name" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Name
          </label>
          <input
            id="channel-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. soc-webhook"
            className={inputClass}
          />
        </div>

        <div>
          <label htmlFor="channel-type" className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
            Type
          </label>
          <select
            id="channel-type"
            value={type}
            disabled={!!existing}
            onChange={(e) => setType(e.target.value)}
            className={inputClass}
          >
            {types.map((t) => (
              <option key={t.type} value={t.type}>
                {t.type} — {t.description}
              </option>
            ))}
          </select>
          {spec?.has_secret && (
            <p className="mt-1 text-xs text-[color:var(--text-3)]">
              This channel stores credentials ({spec.secret_fields?.join(', ')}).
              {existing && ' Submit the masked value to keep the stored secret.'}
            </p>
          )}
        </div>

        {/* Registry-driven typed config form. Secret fields render as
            password inputs; "***" on edit means "keep stored value". */}
        {spec?.fields?.map((field) => (
          <ChannelConfigField
            key={field.name}
            field={field}
            value={config[field.name]}
            onChange={(v) => setConfig((prev) => ({ ...prev, [field.name]: v }))}
            inputClass={inputClass}
          />
        ))}

        <fieldset className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="tabular-nums">enabled</span>
          </label>
        </fieldset>

        {err && (
          <p role="alert" className="text-xs text-[color:var(--danger)]">
            {err}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending}>
            {mutation.isPending ? 'Saving…' : existing ? 'Save changes' : 'Create channel'}
          </Button>
        </div>
      </form>
    </ModalShell>
  );
}

function applyDefaults(
  spec: AlertChannelTypeSpec | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const field of spec?.fields ?? []) {
    if (field.default !== undefined) out[field.name] = field.default;
  }
  return out;
}

function ChannelConfigField({
  field,
  value,
  onChange,
  inputClass,
}: {
  field: AlertFieldSpec;
  value: unknown;
  onChange: (v: unknown) => void;
  inputClass: string;
}) {
  const id = `channel-cfg-${field.name.replace(/\./g, '-')}`;
  const labelEl = (
    <label htmlFor={id} className="block text-xs font-semibold text-[color:var(--text-2)] mb-1">
      {field.label}
      {field.required && <span className="text-[color:var(--danger)]" aria-hidden="true"> *</span>}
    </label>
  );
  const helpEl = field.help && (
    <p className="mt-1 text-xs text-[color:var(--text-3)]">{field.help}</p>
  );

  switch (field.type) {
    case 'boolean':
      return (
        <div>
          <label className="flex items-center gap-2 text-xs text-[color:var(--text-1)]">
            <input
              id={id}
              type="checkbox"
              aria-label={field.label}
              checked={Boolean(value)}
              onChange={(e) => onChange(e.target.checked)}
              className="rounded border-[color:var(--border)] accent-[color:var(--signal)]"
            />
            <span className="tabular-nums">{field.label}</span>
          </label>
          {helpEl}
        </div>
      );
    case 'integer':
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="number"
            aria-label={field.label}
            value={value === undefined || value === null ? '' : String(value)}
            onChange={(e) => {
              const raw = e.target.value;
              onChange(raw === '' ? undefined : Number(raw));
            }}
            placeholder={field.placeholder}
            className={inputClass}
          />
          {helpEl}
        </div>
      );
    case 'secret':
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="password"
            aria-label={field.label}
            value={String(value ?? '')}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            className={inputClass}
          />
          {helpEl}
        </div>
      );
    default:
      return (
        <div>
          {labelEl}
          <input
            id={id}
            type="text"
            aria-label={field.label}
            value={String(value ?? '')}
            onChange={(e) => onChange(e.target.value)}
            placeholder={field.placeholder}
            className={inputClass}
          />
          {helpEl}
        </div>
      );
  }
}

// ---------------------------------------------------------------------------
// Icons — same 24×24 / stroke=1.5 convention as the rest of the app
// ---------------------------------------------------------------------------

function RuleIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M4 6h16M4 12h10M4 18h13" />
      <circle cx="19" cy="17" r="2" />
    </svg>
  );
}

function BellIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </svg>
  );
}
