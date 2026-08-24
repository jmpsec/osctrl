import { useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ArrowRight, FileSearch, Monitor } from 'lucide-react';
import { listNodes } from '$/api/nodes';
import { listQueries } from '$/api/queries';
import type { DistributedQuery, OsqueryNode } from '$/api/types';
import { PlatformIcon, type PlatformId } from '$/components/data/PlatformIcon';
import { StatusPip, type PipVariant } from '$/components/data/StatusPip';
import { formatRelative } from '$/lib/time';

export type SideNavPreviewKind = 'nodes' | 'queries';

export const SIDE_NAV_PREVIEW_ID = 'side-nav-context-preview';

interface SideNavPreviewProps {
  kind: SideNavPreviewKind;
  env: string;
  anchor: { top: number; right: number };
  focusFirstItem?: boolean;
  onDismiss: () => void;
  onInteractionStart: () => void;
  onInteractionEnd: () => void;
}

const PANEL_HEIGHT = 440;
const PANEL_GUTTER = 8;

function platformId(value: string): PlatformId {
  const normalized = value.toLowerCase();
  if (normalized.includes('darwin') || normalized.includes('mac')) return 'darwin';
  if (normalized.includes('windows')) return 'windows';
  if (normalized.includes('freebsd') || normalized.includes('free bsd')) return 'freebsd';
  if (normalized.includes('linux')) return 'linux';
  return 'all';
}

function uniqueNodes(nodes: OsqueryNode[]): OsqueryNode[] {
  return [...new Map(nodes.map((node) => [node.uuid, node])).values()];
}

function isAttentionNode(node: OsqueryNode): boolean {
  return node.health?.status === 'attention'
    || node.health?.status === 'at_risk'
    || node.health?.status === 'offline';
}

function nodeState(node: OsqueryNode, attention: boolean): { label: string; variant: PipVariant } {
  if (node.health?.status === 'at_risk') return { label: 'At risk', variant: 'danger' };
  if (node.health?.status === 'attention') return { label: 'Attention', variant: 'warning' };
  if (node.health?.status === 'offline') return { label: 'Offline', variant: 'dim' };
  if (attention) return { label: 'Inactive', variant: 'dim' };
  return { label: 'Seen recently', variant: 'success' };
}

function queryState(query: DistributedQuery): { label: string; variant: PipVariant } {
  if (query.errors > 0) {
    return {
      label: `${query.errors} ${query.errors === 1 ? 'error' : 'errors'}`,
      variant: 'danger',
    };
  }
  if (query.active) return { label: `${query.executions}/${query.expected} responses`, variant: 'info' };
  if (query.completed) return { label: 'Completed', variant: 'success' };
  if (query.expired) return { label: 'Expired', variant: 'warning' };
  return { label: 'Pending', variant: 'dim' };
}

function PreviewLoading() {
  return (
    <div className="space-y-1 px-2 pb-2" aria-label="Loading preview">
      {[0, 1, 2].map((index) => (
        <div key={index} className="flex items-center gap-2.5 rounded-md px-2 py-2.5">
          <div className="size-7 animate-pulse rounded-md bg-[color:var(--bg-3)]" />
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="h-3 w-2/3 animate-pulse rounded bg-[color:var(--bg-3)]" />
            <div className="h-2.5 w-1/2 animate-pulse rounded bg-[color:var(--bg-2)]" />
          </div>
        </div>
      ))}
    </div>
  );
}

function SectionHeading({ children, count }: { children: React.ReactNode; count?: number }) {
  return (
    <div className="flex items-center justify-between px-4 pb-1.5 pt-3">
      <h3 className="text-xs font-medium text-[color:var(--text-3)]">{children}</h3>
      {count != null && (
        <span className="text-xs tabular-nums text-[color:var(--text-3)]">{count}</span>
      )}
    </div>
  );
}

function EmptySection({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-2 rounded-md px-2 py-2 text-[13px] text-[color:var(--text-3)]">
      {children}
    </div>
  );
}

function NodeRow({ node, env, attention }: { node: OsqueryNode; env: string; attention: boolean }) {
  const state = nodeState(node, attention);
  return (
    <Link
      to="/_app/env/$env/nodes/$uuid"
      params={{ env, uuid: node.uuid }}
      data-preview-item
      className="group mx-2 flex items-center gap-2.5 rounded-md px-2 py-2 hover:bg-[color:var(--bg-2)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[color:var(--accent)]"
    >
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)]">
        <PlatformIcon platform={platformId(node.platform)} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-medium text-[color:var(--text-1)]">
          {node.hostname || node.localname || node.uuid.slice(0, 8)}
        </span>
        <span className="mt-0.5 block truncate text-xs text-[color:var(--text-3)]">
          {attention && node.health?.reason
            ? node.health.reason
            : `Last seen ${formatRelative(node.last_seen)}`}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-1.5 text-xs text-[color:var(--text-2)]">
        <StatusPip variant={state.variant} />
        {state.label}
      </span>
    </Link>
  );
}

function QueryRow({ query, env }: { query: DistributedQuery; env: string }) {
  const state = queryState(query);
  return (
    <Link
      to="/_app/env/$env/queries/$name"
      params={{ env, name: query.name }}
      data-preview-item
      className="group mx-2 flex items-center gap-2.5 rounded-md px-2 py-2 hover:bg-[color:var(--bg-2)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[color:var(--accent)]"
    >
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-[color:var(--border)] bg-[color:var(--bg-0)] text-[color:var(--nav-violet)]">
        <FileSearch size={14} strokeWidth={1.8} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-medium text-[color:var(--text-1)]">
          {query.name}
        </span>
        <span className="mt-0.5 block truncate text-xs text-[color:var(--text-3)]">
          {query.creator ? `${query.creator} · ` : ''}{formatRelative(query.created_at)}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-1.5 text-xs text-[color:var(--text-2)]">
        <StatusPip variant={state.variant} />
        {state.label}
      </span>
    </Link>
  );
}

function NodesPreview({ env }: { env: string }) {
  const recentQuery = useQuery({
    queryKey: ['nodes', env, 'nav-preview', 'recent'],
    queryFn: () => listNodes({ env, status: 'all', sort: 'lastseen', dir: 'desc', page: 1, pageSize: 8 }),
    staleTime: 30_000,
  });
  const inactiveQuery = useQuery({
    queryKey: ['nodes', env, 'nav-preview', 'inactive'],
    queryFn: () => listNodes({ env, status: 'inactive', sort: 'lastseen', dir: 'desc', page: 1, pageSize: 4 }),
    staleTime: 30_000,
  });

  const allAttentionNodes = useMemo(
    () => uniqueNodes([
      ...(recentQuery.data?.items.filter(isAttentionNode) ?? []),
      ...(inactiveQuery.data?.items ?? []),
    ]),
    [inactiveQuery.data?.items, recentQuery.data?.items],
  );
  const attentionNodes = allAttentionNodes.slice(0, 3);
  const attentionIds = new Set(allAttentionNodes.map((node) => node.uuid));
  const recentNodes = (recentQuery.data?.items ?? [])
    .filter((node) => !attentionIds.has(node.uuid))
    .slice(0, 3);

  if (recentQuery.isLoading || inactiveQuery.isLoading) return <PreviewLoading />;
  if (recentQuery.isError && inactiveQuery.isError) {
    return <EmptySection>Node activity is unavailable right now.</EmptySection>;
  }

  return (
    <div className="pb-2">
      <SectionHeading count={allAttentionNodes.length}>Needs attention</SectionHeading>
      {attentionNodes.length > 0
        ? attentionNodes.map((node) => <NodeRow key={node.uuid} node={node} env={env} attention />)
        : <EmptySection>No nodes need attention.</EmptySection>}

      <div className="mx-4 mt-2 border-t border-[color:var(--border)]" />
      <SectionHeading>Recently seen</SectionHeading>
      {recentNodes.length > 0
        ? recentNodes.map((node) => <NodeRow key={node.uuid} node={node} env={env} attention={false} />)
        : <EmptySection>No recent node activity.</EmptySection>}
    </div>
  );
}

function QueriesPreview({ env }: { env: string }) {
  const activeQuery = useQuery({
    queryKey: ['queries', env, 'nav-preview', 'active'],
    queryFn: () => listQueries({ env, target: 'active', sort: 'created', dir: 'desc', page: 1, pageSize: 5 }),
    staleTime: 30_000,
  });
  const recentQuery = useQuery({
    queryKey: ['queries', env, 'nav-preview', 'recent'],
    queryFn: () => listQueries({ env, target: 'all', sort: 'created', dir: 'desc', page: 1, pageSize: 6 }),
    staleTime: 30_000,
  });

  const active = [...(activeQuery.data?.items ?? [])]
    .sort((a, b) => b.errors - a.errors)
    .slice(0, 3);
  const activeIds = new Set(active.map((query) => query.id));
  const recent = (recentQuery.data?.items ?? [])
    .filter((query) => !activeIds.has(query.id))
    .slice(0, 3);

  if (activeQuery.isLoading || recentQuery.isLoading) return <PreviewLoading />;
  if (activeQuery.isError && recentQuery.isError) {
    return <EmptySection>Query activity is unavailable right now.</EmptySection>;
  }

  return (
    <div className="pb-2">
      <SectionHeading count={active.length}>Running now</SectionHeading>
      {active.length > 0
        ? active.map((query) => <QueryRow key={query.id} query={query} env={env} />)
        : <EmptySection>No queries are running.</EmptySection>}

      <div className="mx-4 mt-2 border-t border-[color:var(--border)]" />
      <SectionHeading>Recent</SectionHeading>
      {recent.length > 0
        ? recent.map((query) => <QueryRow key={query.id} query={query} env={env} />)
        : <EmptySection>No recent queries.</EmptySection>}
    </div>
  );
}

export function SideNavPreview({
  kind,
  env,
  anchor,
  focusFirstItem,
  onDismiss,
  onInteractionStart,
  onInteractionEnd,
}: SideNavPreviewProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const title = kind === 'nodes' ? 'Nodes' : 'Queries';
  const destination = kind === 'nodes'
    ? `/_app/env/${env}/nodes`
    : `/_app/env/${env}/queries`;
  const Icon = kind === 'nodes' ? Monitor : FileSearch;
  const top = Math.max(PANEL_GUTTER, Math.min(anchor.top - PANEL_GUTTER, window.innerHeight - PANEL_HEIGHT - PANEL_GUTTER));

  useEffect(() => {
    if (!focusFirstItem) return;
    panelRef.current?.querySelector<HTMLElement>('[data-preview-item]')?.focus();
  }, [focusFirstItem, kind]);

  return createPortal(
    <aside
      id={SIDE_NAV_PREVIEW_ID}
      ref={panelRef}
      aria-label={`${title} activity preview`}
      className="fixed z-[60] max-h-[min(440px,calc(100vh-16px))] w-[340px] overflow-y-auto rounded-lg border border-[color:var(--border-strong)] bg-[color:var(--bg-1)] shadow-[0_14px_40px_rgba(15,23,42,0.14),0_2px_8px_rgba(15,23,42,0.08)]"
      style={{ left: anchor.right + 6, top }}
      onMouseEnter={onInteractionStart}
      onMouseLeave={onInteractionEnd}
      onFocusCapture={onInteractionStart}
      onBlurCapture={onInteractionEnd}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          onDismiss();
        }
      }}
    >
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-[color:var(--border)] bg-[color:var(--bg-1)] px-4 py-3">
        <div className="flex items-center gap-2">
          <Icon size={15} strokeWidth={1.8} className="text-[color:var(--text-2)]" aria-hidden />
          <h2 className="text-sm font-semibold text-[color:var(--text-1)]">{title}</h2>
        </div>
        <Link
          to={destination}
          data-preview-item
          className="flex items-center gap-1 rounded text-xs font-medium text-[color:var(--text-link)] hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--accent)]"
        >
          View all
          <ArrowRight size={12} strokeWidth={1.8} aria-hidden />
        </Link>
      </header>
      {kind === 'nodes' ? <NodesPreview env={env} /> : <QueriesPreview env={env} />}
    </aside>,
    document.body,
  );
}
