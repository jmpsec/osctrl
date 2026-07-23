import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from '@tanstack/react-router';
import { useMutation, useQuery } from '@tanstack/react-query';
import { ArrowLeft, Loader2, Terminal } from 'lucide-react';
import {
  closeConsoleSession,
  createConsoleSession,
  getConsoleCommand,
  getConsoleCommandResults,
  getConsoleSession,
  submitConsoleCommand,
} from '$/api/console';
import { ApiError, AuthError } from '$/api/client';
import type {
  ConsoleCommand,
  ConsoleHistoryEntry,
  ConsoleNodeInfo,
  ConsoleResultRow,
  ConsoleSession,
} from '$/api/types';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';

type Entry =
  | { id: string; type: 'input'; prompt: string; text: string }
  | { id: string; type: 'text'; text: string; tone?: 'error' | 'muted' }
  | { id: string; type: 'table'; rows: ConsoleResultRow[] };

type NodeInfoItem = { label: string; value: string };

const terminalStatuses = new Set(['completed', 'error', 'expired']);
const consoleHeartbeatMs = 10000;
type PendingCommand = { command: ConsoleCommand; path?: string };

export function NodeConsolePage() {
  const { env, uuid } = useParams({ from: '/_app/env/$env/nodes/$uuid/console' });
  return <NodeConsolePanel env={env} uuid={uuid} />;
}

export function NodeConsolePanel({ env, uuid }: { env: string; uuid: string }) {
  const navigate = useNavigate();
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const sessionRef = useRef<ConsoleSession | null>(null);
  const handledCommandRef = useRef<number | null>(null);
  const focusedOnOpenRef = useRef(false);
  const focusAfterCommandRef = useRef(false);
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [nodeInfo, setNodeInfo] = useState<ConsoleNodeInfo | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [pending, setPending] = useState<PendingCommand | null>(null);
  const [osqueryMode, setOsqueryMode] = useState(false);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);
  const sessionID = session?.id;

  useEffect(() => {
    let alive = true;
    void createConsoleSession(env, uuid)
      .then((created) => {
        if (!alive) return;
        sessionRef.current = created.session;
        setSession(created.session);
        setNodeInfo(created.node_info ?? null);
        setEntries(historyToEntries(created.history));
      })
      .catch((error: unknown) => {
        if (!alive) return;
        if (error instanceof AuthError) {
          void navigate({ to: '/login' });
          return;
        }
        setSessionError(error instanceof Error ? error.message : 'Could not open console');
      });
    return () => {
      alive = false;
      const current = sessionRef.current;
      if (current?.active) {
        void closeConsoleSession(env, current.id).catch(() => undefined);
      }
    };
  }, [env, navigate, uuid]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView?.({ block: 'end' });
  }, [entries, pending]);

  useEffect(() => {
    if (!sessionID) return undefined;
    const interval = window.setInterval(() => {
      void getConsoleSession(env, sessionID)
        .then((fresh) => {
          sessionRef.current = fresh;
          setSession(fresh);
        })
        .catch((error: unknown) => {
          if (error instanceof AuthError) {
            void navigate({ to: '/login' });
          }
      });
    }, consoleHeartbeatMs);
    return () => window.clearInterval(interval);
  }, [env, navigate, sessionID]);

  const submitMutation = useMutation({
    mutationFn: async (value: string) => {
      if (!session) throw new Error('Console is not ready');
      return submitConsoleCommand(env, session.id, value, osqueryMode);
    },
    onSuccess: ({ command, parsed }) => {
      if (!session) return;
      setCommandError(null);
      if (parsed.kind === 'mode') {
        setOsqueryMode(true);
        if (parsed.message) {
          const message = parsed.message;
          setEntries((current) => [...current, { id: `mode-${command.id}`, type: 'text', text: message }]);
        }
        return;
      }
      if (parsed.kind === 'exit-mode') {
        setOsqueryMode(false);
        if (parsed.message) {
          const message = parsed.message;
          setEntries((current) => [...current, { id: `mode-${command.id}`, type: 'text', text: message }]);
        }
        return;
      }
      if (parsed.kind === 'carve') {
        setEntries((current) => [
          ...current,
          { id: `carve-${command.id}`, type: 'text', text: parsed.message || 'carve created' },
        ]);
        return;
      }
      if (parsed.kind === 'local') {
        if (parsed.command === 'clear') {
          setEntries([]);
          return;
        }
        if (parsed.output) {
          setEntries((current) => [
            ...current,
            { id: `out-${command.id}`, type: 'text', text: parsed.output ?? '' },
          ]);
        }
        return;
      }
      handledCommandRef.current = null;
      setPending({ command, path: parsed.path });
    },
    onError: (error: unknown) => {
      if (error instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setCommandError(error instanceof Error ? error.message : 'Command failed');
    },
  });

  const commandQuery = useQuery({
    queryKey: ['console-command', env, session?.id, pending?.command.id],
    queryFn: () => getConsoleCommand(env, session!.id, pending!.command.id),
    enabled: Boolean(session && pending),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && terminalStatuses.has(status) ? false : 1000;
    },
    refetchIntervalInBackground: false,
  });

  useEffect(() => {
    const command = commandQuery.data;
    if (!session || !pending || !command || !terminalStatuses.has(command.status)) return;
    if (handledCommandRef.current === command.id) return;
    handledCommandRef.current = command.id;

    void getConsoleCommandResults(env, session.id, command.id)
      .then((rows) => {
        setEntries((current) => [
          ...current,
          command.status === 'completed'
            ? { id: `rows-${command.id}`, type: 'table', rows }
            : {
                id: `err-${command.id}`,
                type: 'text',
                tone: 'error',
                text: command.error || `Command ${command.status}`,
              },
        ]);
        if (command.status === 'completed' && command.input.trim().toLowerCase().startsWith('cd ') && pending.path) {
          setSession((current) => (current ? { ...current, cwd: pending.path ?? current.cwd } : current));
        }
      })
      .catch((error: unknown) => {
        setEntries((current) => [
          ...current,
          {
            id: `err-${command.id}`,
            type: 'text',
            tone: 'error',
            text: error instanceof Error ? error.message : 'Could not load results',
          },
        ]);
      })
      .finally(() => setPending(null));
  }, [commandQuery.data, env, pending, session]);

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = input.trim();
    if (!value || !session || pending || submitMutation.isPending) return;
    setEntries((current) => [
      ...current,
      { id: `in-${Date.now()}`, type: 'input', prompt, text: value },
    ]);
    setInput('');
    focusAfterCommandRef.current = true;
    submitMutation.mutate(value);
  }

  const disabled = !session || Boolean(pending) || submitMutation.isPending;
  const prompt = useMemo(() => (osqueryMode ? 'osquery>' : `${session?.cwd ?? '/'} $`), [osqueryMode, session?.cwd]);
  const nodeInfoItems = useMemo(() => formatNodeInfoItems(nodeInfo), [nodeInfo]);

  function focusCommandInput() {
    if (disabled) return;
    inputRef.current?.focus({ preventScroll: true });
  }

  useEffect(() => {
    if (session && !disabled && !focusedOnOpenRef.current) {
      focusCommandInput();
      focusedOnOpenRef.current = true;
      return;
    }
    if (disabled || !focusAfterCommandRef.current) return;
    focusCommandInput();
    focusAfterCommandRef.current = false;
  }, [commandError, disabled, entries, session]);

  return (
    <div
      data-testid="node-console-page"
      className="flex h-[calc(100dvh-3.5rem)] max-h-[calc(100dvh-3.5rem)] min-h-0 flex-col overflow-hidden px-6 py-4"
    >
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3 border-b border-[color:var(--border)] pb-3">
        <div className="min-w-0 space-y-2">
          <div className="flex min-w-0 items-center gap-3">
            <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] text-[color:var(--signal)]">
              <Terminal className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <h1 className="text-base font-semibold leading-5 text-[color:var(--text-1)]">Console</h1>
              <p className="mt-0.5 truncate font-mono-tabular text-xs text-[color:var(--text-3)]">{uuid}</p>
            </div>
          </div>
          {nodeInfoItems.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {nodeInfoItems.map((item) => (
                <span
                  key={`${item.label}-${item.value}`}
                  className="inline-flex max-w-full items-center gap-1.5 rounded border border-[color:var(--border)] bg-[color:var(--bg-2)] px-2 py-1 text-[11px] leading-none text-[color:var(--text-3)]"
                >
                  <span className="uppercase tracking-normal text-[color:var(--text-4)]">{item.label}</span>
                  <span className="truncate font-mono-tabular text-[color:var(--text-2)]">{item.value}</span>
                </span>
              ))}
            </div>
          )}
        </div>
        <Link
          to="/_app/env/$env/nodes/$uuid"
          params={{ env, uuid }}
          className="inline-flex shrink-0 items-center gap-1.5 rounded border border-[color:var(--border)] bg-[color:var(--bg-1)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-2)] transition-colors hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]"
        >
          <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
          Back
        </Link>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border border-[color:var(--border)] bg-[#050708] text-[#d7f8df] shadow-inner">
        <div className="min-h-0 flex-1 overflow-auto px-4 py-3 font-mono text-xs leading-5" onScroll={focusCommandInput}>
          {sessionError && <Line tone="error" text={sessionError} />}
          {!session && !sessionError && <Line tone="muted" text="opening console..." />}
          {entries.map((entry) => (
            <ConsoleEntry key={entry.id} entry={entry} />
          ))}
          {pending && (
            <div className="flex items-center gap-2 text-[#8fe8a4]" aria-live="polite">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              <span>waiting for node</span>
            </div>
          )}
          {commandError && <Line tone="error" text={commandError} />}
          <div ref={bottomRef} />
        </div>

        <form
          onSubmit={onSubmit}
          data-console-command-bar="true"
          className="sticky bottom-0 z-10 flex shrink-0 items-center gap-2 border-t border-white/10 bg-[#050708] px-4 py-2"
        >
          <span className="shrink-0 font-mono text-xs text-[#8fe8a4]">{prompt}</span>
          <input
            ref={inputRef}
            aria-label="Console input"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            disabled={disabled}
            className="min-w-0 flex-1 bg-transparent font-mono text-xs text-[#d7f8df] outline-none placeholder:text-[#5a705f] disabled:cursor-not-allowed disabled:opacity-60"
            autoComplete="off"
            spellCheck={false}
          />
          <Button type="submit" size="sm" variant="ghost" disabled={disabled || input.trim() === ''}>
            Run
          </Button>
        </form>
      </div>
    </div>
  );
}

function ConsoleEntry({ entry }: { entry: Entry }) {
  if (entry.type === 'input') {
    return (
      <div className="whitespace-pre-wrap">
        <span className="text-[#8fe8a4]">{entry.prompt} </span>
        <span>{entry.text}</span>
      </div>
    );
  }
  if (entry.type === 'table') {
    return <ResultTable rows={entry.rows} />;
  }
  return <Line text={entry.text} tone={entry.tone} />;
}

function historyToEntries(history: ConsoleHistoryEntry[]): Entry[] {
  const entries: Entry[] = [];
  for (const item of history) {
    entries.push({
      id: `history-in-${item.command.id}`,
      type: 'input',
      prompt: '$',
      text: item.command.input,
    });
    if (item.command.error) {
      entries.push({
        id: `history-err-${item.command.id}`,
        type: 'text',
        tone: 'error',
        text: item.command.error,
      });
    }
    if (item.results.length > 0) {
      entries.push({
        id: `history-rows-${item.command.id}`,
        type: 'table',
        rows: item.results,
      });
    }
  }
  return entries;
}

function formatNodeInfoItems(info: ConsoleNodeInfo | null): NodeInfoItem[] {
  if (!info) return [];
  const items: NodeInfoItem[] = [];
  if (info.ip_address) items.push({ label: 'ip', value: info.ip_address });
  if (info.osquery_user) items.push({ label: 'user', value: info.osquery_user });
  if (info.osquery_version) items.push({ label: 'osquery', value: info.osquery_version });
  const platform = [info.platform, info.platform_version].filter(Boolean).join(' ');
  if (platform) items.push({ label: 'platform', value: platform });
  return items;
}

function Line({ text, tone }: { text: string; tone?: 'error' | 'muted' }) {
  return (
    <div
      className={cn(
        'whitespace-pre-wrap',
        tone === 'error' && 'text-[#ff8a8a]',
        tone === 'muted' && 'text-[#7d8b80]',
      )}
    >
      {text}
    </div>
  );
}

function ResultTable({ rows }: { rows: ConsoleResultRow[] }) {
  if (rows.length === 0) {
    return <Line tone="muted" text="no rows" />;
  }
  const columns = Array.from(rows.reduce((set, row) => {
    Object.keys(row).forEach((key) => set.add(key));
    return set;
  }, new Set<string>()));

  return (
    <div className="my-1 overflow-x-auto">
      <table className="min-w-full border-collapse text-left">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column} className="border-b border-white/15 pr-4 py-1 font-medium text-[#8fe8a4]">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column} className="max-w-[28rem] truncate pr-4 py-1 text-[#d7f8df]">
                  {String(row[column] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
