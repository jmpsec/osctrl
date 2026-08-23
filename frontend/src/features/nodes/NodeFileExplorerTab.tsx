import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link } from '@tanstack/react-router';
import { Archive, ChevronDown, ChevronRight, ExternalLink, File, Folder, Loader2, RefreshCw } from 'lucide-react';
import { runCarve } from '$/api/carves';
import { AuthError } from '$/api/client';
import {
  closeFileExplorerSession,
  createFileExplorerSession,
  getFileExplorerPrimingMetadata,
  getFileExplorerRequest,
  getFileExplorerRequestResults,
  getFileExplorerSession,
  listFileExplorerDirectory,
  statFileExplorerPath,
} from '$/api/file-explorer';
import type {
  FileExplorerEntry,
  FileExplorerMetadataRow,
  FileExplorerRequest,
  FileExplorerSession,
} from '$/api/types';
import { cn } from '$/lib/cn';

type EntriesByDirectory = Record<string, FileExplorerEntry[]>;
type CarveStatus =
  | { kind: 'success'; name: string }
  | { kind: 'error'; message: string };

const terminalStatuses = new Set(['completed', 'error', 'expired']);
const heartbeatMs = 10000;
const maxPolls = 30;

export function NodeFileExplorerTab({ env, uuid }: { env: string; uuid: string }) {
  const sessionRef = useRef<FileExplorerSession | null>(null);
  const loadingPathsRef = useRef<Set<string>>(new Set());
  const [session, setSession] = useState<FileExplorerSession | null>(null);
  const [primingRequest, setPrimingRequest] = useState<FileExplorerRequest | null>(null);
  const [primingMetadata, setPrimingMetadata] = useState<FileExplorerMetadataRow | null>(null);
  const [entriesByDirectory, setEntriesByDirectory] = useState<EntriesByDirectory>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loadingPaths, setLoadingPaths] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<FileExplorerEntry | null>(null);
  const [carving, setCarving] = useState(false);
  const [carveStatus, setCarveStatus] = useState<CarveStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const updateLoadingPath = useCallback((path: string, loading: boolean) => {
    const next = new Set(loadingPathsRef.current);
    if (loading) next.add(path);
    else next.delete(path);
    loadingPathsRef.current = next;
    setLoadingPaths(next);
  }, []);

  const runRequest = useCallback(async (activeSession: FileExplorerSession, request: FileExplorerRequest) => {
    const completed = await waitForRequest(env, activeSession.id, request.id);
    if (completed.status !== 'completed') {
      throw new Error(completed.error || `Request ${completed.status}`);
    }
    return getFileExplorerRequestResults(env, activeSession.id, request.id);
  }, [env]);

  const loadDirectory = useCallback(async (activeSession: FileExplorerSession, path: string) => {
    if (loadingPathsRef.current.has(path)) return;
    updateLoadingPath(path, true);
    setError(null);
    try {
      const request = await listFileExplorerDirectory(env, activeSession.id, path);
      const rows = await runRequest(activeSession, request);
      setEntriesByDirectory((current) => ({ ...current, [path]: sortEntries(rows) }));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Could not list directory');
    } finally {
      updateLoadingPath(path, false);
    }
  }, [env, runRequest, updateLoadingPath]);

  const statEntry = useCallback(async (entry: FileExplorerEntry) => {
    const activeSession = sessionRef.current;
    if (!activeSession) return;
    setSelected(entry);
    setCarveStatus(null);
    if (entry.type === 'directory') return;
    setError(null);
    try {
      const request = await statFileExplorerPath(env, activeSession.id, entry.path);
      const rows = await runRequest(activeSession, request);
      setSelected(rows[0] ?? entry);
    } catch (statError) {
      setError(statError instanceof Error ? statError.message : 'Could not stat path');
    }
  }, [env, runRequest]);

  useEffect(() => {
    let alive = true;
    void createFileExplorerSession(env, uuid)
      .then((created) => {
        if (!alive) return;
        sessionRef.current = created.session;
        setSession(created.session);
        setExpanded(new Set([created.session.root]));
        setPrimingRequest(created.priming ?? null);
        void loadDirectory(created.session, created.session.root);
      })
      .catch((createError: unknown) => {
        if (!alive) return;
        setError(createError instanceof Error ? createError.message : 'Could not open file explorer');
      });
    return () => {
      alive = false;
      const current = sessionRef.current;
      if (current?.active) {
        void closeFileExplorerSession(env, current.id).catch(() => undefined);
      }
    };
  }, [env, loadDirectory, uuid]);

  // Poll the priming metadata request until it reaches a terminal
  // status, then fetch its osquery_info rows and surface live metadata
  // in the file explorer header. The priming query's presence in the
  // node's pending queue also warms acceleration so the first directory
  // listing is delivered on the next fast poll.
  useEffect(() => {
    const activeSession = sessionRef.current;
    if (!activeSession || !primingRequest) return;
    let alive = true;
    void (async () => {
      try {
        const completed = await waitForRequest(env, activeSession.id, primingRequest.id);
        if (!alive || completed.status !== 'completed') {
          if (alive) setPrimingRequest(null);
          return;
        }
        const rows = await getFileExplorerPrimingMetadata(env, activeSession.id, primingRequest.id);
        if (!alive) return;
        if (rows.length > 0) setPrimingMetadata(rows[0] as FileExplorerMetadataRow);
      } catch {
        // Priming is best-effort; ignore errors.
      } finally {
        if (alive) setPrimingRequest(null);
      }
    })();
    return () => {
      alive = false;
    };
  }, [env, primingRequest]);

  useEffect(() => {
    const sessionID = session?.id;
    if (!sessionID) return undefined;
    const interval = window.setInterval(() => {
      void getFileExplorerSession(env, sessionID)
        .then((fresh) => {
          sessionRef.current = fresh;
          setSession(fresh);
        })
        .catch(() => undefined);
    }, heartbeatMs);
    return () => window.clearInterval(interval);
  }, [env, session?.id]);

  const root = session?.root ?? '/';
  const rootEntries = entriesByDirectory[root] ?? [];
  const rootLoading = loadingPaths.has(root);
  const refreshPath = selected?.type === 'directory' ? selected.path : selected?.directory || root;
  const refreshLoading = loadingPaths.has(refreshPath);

  function onRefresh() {
    const activeSession = sessionRef.current;
    if (!activeSession) return;
    void loadDirectory(activeSession, refreshPath);
  }

  async function onCarveSelected() {
    if (!selected || carving) return;
    setCarving(true);
    setCarveStatus(null);
    try {
      const result = await runCarve(env, { path: selected.path, uuid_list: [uuid] });
      setCarveStatus({ kind: 'success', name: result.query_name });
    } catch (carveError) {
      if (carveError instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setCarveStatus({
        kind: 'error',
        message: carveError instanceof Error ? carveError.message : 'Carve failed',
      });
    } finally {
      setCarving(false);
    }
  }

  async function onEntryClick(entry: FileExplorerEntry) {
    await statEntry(entry);
    if (entry.type !== 'directory') return;
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(entry.path)) next.delete(entry.path);
      else next.add(entry.path);
      return next;
    });
    if (!entriesByDirectory[entry.path] && !loadingPathsRef.current.has(entry.path)) {
      const activeSession = sessionRef.current;
      if (activeSession) {
        void loadDirectory(activeSession, entry.path);
      }
    }
  }

  const primingItems = useMemo(() => formatPrimingItems(primingMetadata), [primingMetadata]);

  return (
    <section className="min-h-[360px] border border-[color:var(--border)] rounded-lg bg-[color:var(--bg-1)]">
      <div className="flex items-center justify-between gap-3 border-b border-[color:var(--border)] px-3 py-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-[color:var(--text-1)]">File Explorer</h2>
            {primingRequest && (
              <span
                className="inline-flex items-center gap-1 rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] px-1.5 py-0.5 text-xs leading-none text-[color:var(--text-3)]"
                title="Warming file explorer metadata"
              >
                <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
                warming
              </span>
            )}
          </div>
          <p className="font-mono-tabular text-xs text-[color:var(--text-3)] truncate">{root}</p>
          {primingItems.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1.5">
              {primingItems.map((item) => (
                <span
                  key={`${item.label}-${item.value}`}
                  className="inline-flex max-w-full items-center gap-1.5 rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] px-1.5 py-0.5 text-xs leading-none text-[color:var(--text-3)]"
                >
                  <span className="uppercase tracking-normal text-[color:var(--text-4)]">{item.label}</span>
                  <span className="truncate font-mono-tabular text-[color:var(--text-2)]">{item.value}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <button
          type="button"
          aria-label={`Refresh ${refreshPath}`}
          onClick={onRefresh}
          disabled={!session || refreshLoading}
          className={cn(
            'inline-flex h-8 items-center justify-center gap-2 rounded border border-[color:var(--border)] px-2.5',
            'text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)]',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          {refreshLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          <span className="text-xs">{refreshLoading ? 'Loading...' : 'Refresh'}</span>
        </button>
      </div>

      {error && (
        <div role="alert" className="border-b border-[color:var(--border)] px-3 py-2 text-xs text-[color:var(--danger)]">
          {error}
        </div>
      )}

      <div className="grid min-h-[320px] grid-cols-1 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="overflow-auto">
          {rootLoading && rootEntries.length === 0 ? (
            <LoadingRow depth={0} />
          ) : (
            <div role="tree" aria-label="Node files" className="py-1">
              {renderEntries(rootEntries, 0, expanded, loadingPaths, entriesByDirectory, selected?.path, onEntryClick)}
            </div>
          )}
        </div>
        <FileDetails
          env={env}
          entry={selected}
          carving={carving}
          carveStatus={carveStatus}
          onCarveSelected={onCarveSelected}
        />
      </div>
    </section>
  );
}

function renderEntries(
  entries: FileExplorerEntry[],
  depth: number,
  expanded: Set<string>,
  loadingPaths: Set<string>,
  entriesByDirectory: EntriesByDirectory,
  selectedPath: string | undefined,
  onEntryClick: (entry: FileExplorerEntry) => void,
): ReactNode {
  return entries.map((entry) => {
    const isDirectory = entry.type === 'directory';
    const isExpanded = expanded.has(entry.path);
    const isLoading = loadingPaths.has(entry.path);
    const isSelected = selectedPath === entry.path;
    const childEntries = entriesByDirectory[entry.path]?.filter((child) => child.path !== entry.path);
    const name = entry.filename || entry.path;
    return (
      <div key={entry.path}>
        <button
          type="button"
          role="treeitem"
          aria-expanded={isDirectory ? isExpanded : undefined}
          aria-selected={isSelected || undefined}
          aria-label={`${name} ${isDirectory ? 'directory' : 'file'}`}
          onClick={() => onEntryClick(entry)}
          className={cn(
            'grid w-full grid-cols-[auto_auto_minmax(0,1fr)_auto] items-center gap-2 px-3 py-1.5 text-left text-xs',
            'text-[color:var(--text-2)] hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)]',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
            isSelected && 'bg-[color:var(--bg-2)] text-[color:var(--text-1)]',
          )}
          style={{ paddingLeft: `${12 + depth * 18}px` }}
        >
          {isDirectory ? (
            isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />
          ) : (
            <span className="h-3.5 w-3.5" />
          )}
          {isDirectory ? <Folder className="h-3.5 w-3.5" /> : <File className="h-3.5 w-3.5" />}
          <span className="truncate font-medium">{name}</span>
          <span className="font-mono-tabular text-xs text-[color:var(--text-3)]">
            {isLoading ? <LoadingInline /> : formatSize(entry.size)}
          </span>
        </button>
        {isDirectory && isExpanded && isLoading && !childEntries && <LoadingRow depth={depth + 1} />}
        {isDirectory && isExpanded && childEntries && renderEntries(
          childEntries,
          depth + 1,
          expanded,
          loadingPaths,
          entriesByDirectory,
          selectedPath,
          onEntryClick,
        )}
      </div>
    );
  });
}

function FileDetails({
  env,
  entry,
  carving,
  carveStatus,
  onCarveSelected,
}: {
  env: string;
  entry: FileExplorerEntry | null;
  carving: boolean;
  carveStatus: CarveStatus | null;
  onCarveSelected: () => void;
}) {
  const rows = useMemo(() => {
    if (!entry) return [];
    return [
      ['Path', entry.path],
      ['Type', entry.type],
      ['Size', formatSize(entry.size)],
      ['Mode', entry.mode ?? ''],
      ['UID', entry.uid ?? ''],
      ['GID', entry.gid ?? ''],
      ['Modified', formatUnix(entry.mtime)],
      ['Accessed', formatUnix(entry.atime)],
      ['Changed', formatUnix(entry.ctime)],
    ].filter(([, value]) => value !== '');
  }, [entry]);

  return (
    <aside
      aria-label="File details"
      className={cn(
        'border-t border-[color:var(--border)] bg-[color:var(--bg-0)] p-3',
        'lg:sticky lg:top-3 lg:self-start lg:border-l lg:border-t-0',
        'lg:max-h-[calc(100vh-1.5rem)] lg:overflow-auto',
      )}
    >
      <h3 className="mb-2 text-xs font-semibold text-[color:var(--text-1)]">Details</h3>
      {entry ? (
        <dl className="space-y-2">
          {rows.map(([label, value]) => (
            <div key={label}>
              <dt className="text-xs uppercase tracking-[0.12em] text-[color:var(--text-3)]">{label}</dt>
              <dd className="break-all font-mono-tabular text-xs text-[color:var(--text-1)]">{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <div className="text-xs text-[color:var(--text-3)]">No selection</div>
      )}
      <div className="mt-4 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-1)] p-3">
        <h4 className="text-xs font-semibold text-[color:var(--text-1)]">Carve</h4>
        <p className="mt-1 break-all font-mono-tabular text-xs text-[color:var(--text-3)]">
          {entry?.path ?? 'No path selected'}
        </p>
        <button
          type="button"
          onClick={onCarveSelected}
          disabled={!entry || carving}
          className={cn(
            'mt-3 inline-flex h-8 w-full items-center justify-center gap-2 rounded border border-[color:var(--border)] px-3',
            'bg-[color:var(--signal)] text-xs font-medium text-[color:var(--accent-contrast)] hover:bg-[color:var(--signal-bright)]',
            'disabled:cursor-not-allowed disabled:opacity-50',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
          )}
        >
          {carving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Archive className="h-3.5 w-3.5" />}
          {carving ? 'Starting...' : 'Carve selected'}
        </button>
        {carveStatus?.kind === 'success' && (
          <p
            className="mt-2 text-xs text-[color:var(--success)]"
          >
            Created new{' '}
            <Link
              to="/_app/env/$env/carves/$name"
              params={{ env, name: carveStatus.name }}
              className={cn(
                'inline-flex items-center gap-1 font-medium underline decoration-current/40 underline-offset-2',
                'hover:text-[color:var(--signal)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              )}
            >
              carve
              <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </Link>
          </p>
        )}
        {carveStatus?.kind === 'error' && (
          <p
            role="alert"
            className="mt-2 break-all text-xs text-[color:var(--danger)]"
          >
            {carveStatus.message}
          </p>
        )}
      </div>
    </aside>
  );
}

function LoadingInline() {
  return (
    <span className="inline-flex items-center gap-1">
      <Loader2 className="h-3 w-3 animate-spin" />
      Loading...
    </span>
  );
}

function LoadingRow({ depth }: { depth: number }) {
  return (
    <div
      className="flex items-center gap-2 px-3 py-2 text-xs text-[color:var(--text-3)]"
      style={{ paddingLeft: `${12 + depth * 18}px` }}
    >
      <Loader2 className="h-3.5 w-3.5 animate-spin" />
      Loading...
    </div>
  );
}

async function waitForRequest(env: string, sessionId: number, requestId: number): Promise<FileExplorerRequest> {
  for (let i = 0; i < maxPolls; i += 1) {
    const request = await getFileExplorerRequest(env, sessionId, requestId);
    if (terminalStatuses.has(request.status)) {
      return request;
    }
    await delay(1000);
  }
  throw new Error('file explorer request timed out');
}

function delay(ms: number) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function sortEntries(entries: FileExplorerEntry[]) {
  return [...entries].sort((a, b) => {
    if (a.type === 'directory' && b.type !== 'directory') return -1;
    if (a.type !== 'directory' && b.type === 'directory') return 1;
    return (a.filename || a.path).localeCompare(b.filename || b.path);
  });
}

function formatSize(size?: number) {
  if (!size) return '';
  if (size >= 1_000_000_000) return `${(size / 1_000_000_000).toFixed(1)} GB`;
  if (size >= 1_000_000) return `${(size / 1_000_000).toFixed(1)} MB`;
  if (size >= 1_000) return `${(size / 1_000).toFixed(0)} KB`;
  return `${size} B`;
}

function formatUnix(value?: number) {
  if (!value) return '';
  return new Date(value * 1000).toLocaleString();
}

type PrimingItem = { label: string; value: string };

function formatPrimingItems(metadata: FileExplorerMetadataRow | null): PrimingItem[] {
  if (!metadata) return [];
  const items: PrimingItem[] = [];
  const version = typeof metadata.version === 'string' ? (metadata.version as string) : '';
  const build = typeof metadata.build_platform === 'string' ? (metadata.build_platform as string) : '';
  const distro = typeof metadata.build_distro === 'string' ? (metadata.build_distro as string) : '';
  const startTime = metadata.start_time != null ? String(metadata.start_time) : '';
  const configValid = typeof metadata.config_valid === 'string' ? (metadata.config_valid as string) : '';
  if (version) items.push({ label: 'osquery', value: version });
  if (build) {
    const value = [build, distro].filter(Boolean).join(' ');
    items.push({ label: 'build', value });
  }
  if (startTime) {
    const secs = Number(startTime);
    if (!Number.isNaN(secs) && secs > 0) {
      const uptimeMs = Date.now() - secs * 1000;
      if (uptimeMs > 0) items.push({ label: 'uptime', value: formatUptimeBrief(uptimeMs) });
    }
  }
  if (configValid) items.push({ label: 'config', value: configValid });
  return items;
}

function formatUptimeBrief(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
