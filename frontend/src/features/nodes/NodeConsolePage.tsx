import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from '@tanstack/react-router';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Loader2, Terminal } from 'lucide-react';
import {
  closeConsoleSession,
  createConsoleSession,
  getConsoleCommand,
  getConsoleCommandResults,
  submitConsoleCommand,
} from '$/api/console';
import { ApiError, AuthError } from '$/api/client';
import type { ConsoleCommand, ConsoleResultRow, ConsoleSession } from '$/api/types';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';

type Entry =
  | { id: string; type: 'input'; cwd: string; text: string }
  | { id: string; type: 'text'; text: string; tone?: 'error' | 'muted' }
  | { id: string; type: 'table'; rows: ConsoleResultRow[] };

const terminalStatuses = new Set(['completed', 'error', 'expired']);
type PendingCommand = { command: ConsoleCommand; path?: string };

export function NodeConsolePage() {
  const { env, uuid } = useParams({ from: '/_app/env/$env/nodes/$uuid/console' });
  return <NodeConsolePanel env={env} uuid={uuid} />;
}

export function NodeConsolePanel({ env, uuid }: { env: string; uuid: string }) {
  const navigate = useNavigate();
  const bottomRef = useRef<HTMLDivElement | null>(null);
  const sessionRef = useRef<ConsoleSession | null>(null);
  const handledCommandRef = useRef<number | null>(null);
  const [session, setSession] = useState<ConsoleSession | null>(null);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [input, setInput] = useState('');
  const [pending, setPending] = useState<PendingCommand | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [commandError, setCommandError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void createConsoleSession(env, uuid)
      .then((created) => {
        if (!alive) return;
        sessionRef.current = created;
        setSession(created);
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

  const submitMutation = useMutation({
    mutationFn: async (value: string) => {
      if (!session) throw new Error('Console is not ready');
      return submitConsoleCommand(env, session.id, value);
    },
    onSuccess: ({ command, parsed }) => {
      if (!session) return;
      setCommandError(null);
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
      { id: `in-${Date.now()}`, type: 'input', cwd: session.cwd, text: value },
    ]);
    setInput('');
    submitMutation.mutate(value);
  }

  const disabled = !session || Boolean(pending) || submitMutation.isPending;
  const prompt = useMemo(() => `${session?.cwd ?? '/'} $`, [session?.cwd]);

  return (
    <div className="flex h-full min-h-0 flex-col px-6 py-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[color:var(--text-1)]">
            <Terminal className="h-4 w-4 text-[color:var(--signal)]" aria-hidden="true" />
            <h1 className="text-base font-semibold">Console</h1>
          </div>
          <p className="mt-0.5 truncate font-mono-tabular text-xs text-[color:var(--text-3)]">{uuid}</p>
        </div>
        <Link
          to="/_app/env/$env/nodes/$uuid"
          params={{ env, uuid }}
          className="rounded border border-[color:var(--border)] px-3 py-1.5 text-xs font-medium text-[color:var(--text-2)] transition-colors hover:bg-[color:var(--bg-2)] hover:text-[color:var(--text-1)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]"
        >
          Back
        </Link>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border border-[color:var(--border)] bg-[#050708] text-[#d7f8df] shadow-inner">
        <div className="flex-1 overflow-auto px-4 py-3 font-mono text-xs leading-5">
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

        <form onSubmit={onSubmit} className="flex items-center gap-2 border-t border-white/10 px-4 py-2">
          <span className="shrink-0 font-mono text-xs text-[#8fe8a4]">{prompt}</span>
          <input
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
        <span className="text-[#8fe8a4]">{entry.cwd} $ </span>
        <span>{entry.text}</span>
      </div>
    );
  }
  if (entry.type === 'table') {
    return <ResultTable rows={entry.rows} />;
  }
  return <Line text={entry.text} tone={entry.tone} />;
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
