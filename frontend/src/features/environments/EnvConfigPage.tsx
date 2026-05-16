import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate, Link } from '@tanstack/react-router';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getEnvironment,
  getEnvironmentConfig,
  patchEnvironmentConfig,
  patchEnvironmentIntervals,
  patchEnvironmentExpiration,
  type EnvConfigResponse,
  type EnvConfigPatchRequest,
  type EnvExpirationAction,
} from '$/api/environments';
import { AuthError, ApiError } from '$/api/client';
import { cn } from '$/lib/cn';
import { CodeEditor } from '$/components/forms/CodeEditor';
import { DiffView } from '$/components/forms/DiffView';

type SectionKey = 'options' | 'schedule' | 'packs' | 'decorators' | 'atc' | 'flags';

const SECTIONS: { key: SectionKey; label: string; language: string; help: string }[] = [
  { key: 'options', label: 'Options', language: 'json', help: 'Top-level osquery `options` block.' },
  { key: 'schedule', label: 'Schedule', language: 'json', help: 'Scheduled query map keyed by name.' },
  { key: 'packs', label: 'Packs', language: 'json', help: 'Named query packs delivered with the config.' },
  { key: 'decorators', label: 'Decorators', language: 'json', help: 'Decorator queries that prefix every result.' },
  { key: 'atc', label: 'ATC', language: 'json', help: 'Auto Table Construction — third-party SQLite virtual tables.' },
  { key: 'flags', label: 'Flags', language: 'plaintext', help: 'CLI flags appended to osquery on startup.' },
];

export function EnvConfigPage() {
  const { env } = useParams({ from: '/_app/env/$env/config' });
  const navigate = useNavigate({ from: '/_app/env/$env/config' });
  const qc = useQueryClient();

  const envQuery = useQuery({
    queryKey: ['environment', env],
    queryFn: () => getEnvironment(env),
    staleTime: 60_000,
  });

  const cfgQuery = useQuery({
    queryKey: ['environment-config', env],
    queryFn: () => getEnvironmentConfig(env),
    staleTime: 60_000,
  });

  // Local working buffer keyed by section. We seed it from the server snapshot
  // the first time the data arrives, then leave the user's edits alone until
  // they save or explicitly reset.
  const [draft, setDraft] = useState<EnvConfigResponse | null>(null);
  const [saveErr, setSaveErr] = useState<string | null>(null);
  const [diffsOpen, setDiffsOpen] = useState<Record<SectionKey, boolean>>({
    options: false,
    schedule: false,
    packs: false,
    decorators: false,
    atc: false,
    flags: false,
  });

  useEffect(() => {
    if (cfgQuery.data && draft === null) {
      setDraft(cfgQuery.data);
    }
  }, [cfgQuery.data, draft]);

  const dirty = useMemo(() => {
    if (!cfgQuery.data || !draft) return new Set<SectionKey>();
    const out = new Set<SectionKey>();
    for (const { key } of SECTIONS) {
      if (cfgQuery.data[key] !== draft[key]) out.add(key);
    }
    return out;
  }, [cfgQuery.data, draft]);

  const saveAll = useMutation({
    mutationFn: () => {
      if (!cfgQuery.data || !draft) {
        throw new Error('No data loaded.');
      }
      const body: EnvConfigPatchRequest = {};
      for (const { key } of SECTIONS) {
        if (cfgQuery.data[key] !== draft[key]) {
          body[key] = draft[key];
        }
      }
      return patchEnvironmentConfig(env, body);
    },
    onSuccess: (data) => {
      setDraft(data);
      setSaveErr(null);
      void qc.invalidateQueries({ queryKey: ['environment-config', env] });
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        setSaveErr(e.message);
        return;
      }
      setSaveErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  const saveOne = useMutation({
    mutationFn: ({ key, value }: { key: SectionKey; value: string }) => {
      const body: EnvConfigPatchRequest = { [key]: value };
      return patchEnvironmentConfig(env, body);
    },
    onSuccess: (data) => {
      setDraft(data);
      setSaveErr(null);
      void qc.invalidateQueries({ queryKey: ['environment-config', env] });
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      if (e instanceof ApiError && e.status === 400) {
        setSaveErr(e.message);
        return;
      }
      setSaveErr(e instanceof Error ? e.message : 'Save failed');
    },
  });

  if (envQuery.isError && envQuery.error instanceof AuthError) {
    void navigate({ to: '/login' });
    return null;
  }

  if (envQuery.isLoading || cfgQuery.isLoading || !draft) {
    return (
      <div className="p-6">
        <div className="h-6 w-48 bg-[color:var(--bg-3)] rounded animate-pulse mb-4" />
        <div className="h-32 w-full bg-[color:var(--bg-3)] rounded animate-pulse" />
      </div>
    );
  }

  if (envQuery.isError || cfgQuery.isError) {
    const err = envQuery.error ?? cfgQuery.error;
    return (
      <div className="p-6 text-sm">
        <p className="text-[color:var(--danger)]">
          {err instanceof Error ? err.message : 'Failed to load environment config.'}
        </p>
      </div>
    );
  }

  const envInfo = envQuery.data;

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <Link
          to="/_app/environments"
          className="text-xs text-[color:var(--text-3)] hover:text-[color:var(--text-1)]"
        >
          ← Environments
        </Link>
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
          {envInfo?.name ?? env}
        </h1>
        <span className="text-xs font-mono-tabular text-[color:var(--text-3)]">
          {envInfo?.uuid}
        </span>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-[10px] font-mono-tabular text-[color:var(--text-3)]">
            {dirty.size > 0 ? `${dirty.size} unsaved section${dirty.size === 1 ? '' : 's'}` : 'all sections saved'}
          </span>
          <button
            type="button"
            onClick={() => {
              if (cfgQuery.data) setDraft(cfgQuery.data);
              setSaveErr(null);
            }}
            disabled={dirty.size === 0}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)] transition-colors',
              'disabled:opacity-40 disabled:cursor-not-allowed',
            )}
          >
            Reset
          </button>
          <button
            type="button"
            disabled={dirty.size === 0 || saveAll.isPending}
            onClick={() => saveAll.mutate()}
            className={cn(
              'px-3 py-1.5 text-xs font-medium rounded-md',
              'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
              'transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            {saveAll.isPending ? 'Saving…' : 'Save all changes'}
          </button>
        </div>
      </div>

      {saveErr && (
        <div className="px-4 py-2 border-b border-[color:var(--border)]">
          <p
            role="alert"
            className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
          >
            {saveErr}
          </p>
        </div>
      )}

      <div className="flex-1 overflow-auto min-h-0 p-4 space-y-4">
        {envInfo && (
          <IntervalsCard env={env} envInfo={envInfo} qc={qc} />
        )}
        {envInfo && (
          <ExpirationCard env={env} qc={qc} />
        )}
        {SECTIONS.map(({ key, label, language, help }) => {
          const isDirty = dirty.has(key);
          const before = cfgQuery.data?.[key] ?? '';
          const after = draft[key];
          return (
            <section
              key={key}
              className="border border-[color:var(--border)] rounded-md overflow-hidden bg-[color:var(--bg-1)]"
            >
              <header className="flex items-center gap-3 px-3 py-2 bg-[color:var(--bg-0)] border-b border-[color:var(--border)]">
                <h2
                  id={`section-${key}-label`}
                  className="font-display text-sm font-semibold text-[color:var(--text-1)]"
                >
                  {label}
                </h2>
                <p className="text-[10px] text-[color:var(--text-3)] truncate flex-1">{help}</p>
                {isDirty && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-[rgba(var(--warning-r),var(--warning-g),var(--warning-b),0.12)] text-[color:var(--warning)]">
                    pending
                  </span>
                )}
                <button
                  type="button"
                  disabled={!isDirty}
                  onClick={() =>
                    setDiffsOpen((s) => ({ ...s, [key]: !s[key] }))
                  }
                  className={cn(
                    'text-[10px] px-2 py-0.5 rounded text-[color:var(--text-2)] hover:text-[color:var(--text-1)] hover:bg-[color:var(--bg-2)]',
                    'disabled:opacity-40 disabled:cursor-not-allowed',
                  )}
                >
                  {diffsOpen[key] ? 'Hide diff' : 'Show diff'}
                </button>
                <button
                  type="button"
                  disabled={!isDirty || saveOne.isPending}
                  onClick={() => saveOne.mutate({ key, value: after })}
                  className={cn(
                    'text-[10px] px-2 py-0.5 rounded font-medium',
                    'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
                    'disabled:opacity-40 disabled:cursor-not-allowed',
                  )}
                >
                  Save section
                </button>
              </header>
              <CodeEditor
                aria-labelledby={`section-${key}-label`}
                value={after}
                language={language}
                onChange={(v) =>
                  setDraft((d) => (d ? { ...d, [key]: v } : d))
                }
                height="280px"
              />
              {isDirty && diffsOpen[key] && (
                <div className="p-3 border-t border-[color:var(--border)]">
                  <DiffView before={before} after={after} />
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Intervals card
// ---------------------------------------------------------------------------
function IntervalsCard({
  env,
  envInfo,
  qc,
}: {
  env: string;
  envInfo: { config_interval: number; log_interval: number; query_interval: number };
  qc: ReturnType<typeof useQueryClient>;
}) {
  const [cfg, setCfg] = useState(envInfo.config_interval);
  const [lg, setLg] = useState(envInfo.log_interval);
  const [qr, setQr] = useState(envInfo.query_interval);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setCfg(envInfo.config_interval);
    setLg(envInfo.log_interval);
    setQr(envInfo.query_interval);
  }, [envInfo.config_interval, envInfo.log_interval, envInfo.query_interval]);

  const dirty =
    cfg !== envInfo.config_interval ||
    lg !== envInfo.log_interval ||
    qr !== envInfo.query_interval;

  const mutation = useMutation({
    mutationFn: () =>
      patchEnvironmentIntervals(env, {
        config_interval: cfg,
        log_interval: lg,
        query_interval: qr,
      }),
    onSuccess: () => {
      setErr(null);
      void qc.invalidateQueries({ queryKey: ['environment', env] });
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Update failed');
    },
  });

  return (
    <section className="border border-[color:var(--border)] rounded-md bg-[color:var(--bg-1)] p-4">
      <h2 className="font-display text-sm font-semibold text-[color:var(--text-1)] mb-2">
        Pull intervals
      </h2>
      <p className="text-[10px] text-[color:var(--text-3)] mb-3">
        How often each node should poll for config / log / query updates (seconds).
      </p>
      <div className="grid grid-cols-3 gap-3">
        <IntervalField id="iv-cfg" label="config_interval" value={cfg} onChange={setCfg} />
        <IntervalField id="iv-log" label="log_interval" value={lg} onChange={setLg} />
        <IntervalField id="iv-qry" label="query_interval" value={qr} onChange={setQr} />
      </div>

      {err && (
        <p
          role="alert"
          className="mt-3 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
        >
          {err}
        </p>
      )}

      <div className="flex justify-end mt-3">
        <button
          type="button"
          disabled={!dirty || mutation.isPending}
          onClick={() => mutation.mutate()}
          className={cn(
            'px-3 py-1.5 text-xs font-medium rounded-md',
            'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
            'transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
          )}
        >
          {mutation.isPending ? 'Saving…' : 'Save intervals'}
        </button>
      </div>
    </section>
  );
}

function IntervalField({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label
        htmlFor={id}
        className="block text-xs font-semibold text-[color:var(--text-2)] mb-1 font-mono-tabular"
      >
        {label}
      </label>
      <input
        id={id}
        type="number"
        min={1}
        value={value}
        onChange={(e) => {
          const v = Number(e.target.value);
          if (!Number.isNaN(v) && v >= 1) onChange(v);
        }}
        className={cn(
          'w-full px-3 py-2 text-sm rounded-md border border-[color:var(--border)]',
          'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular',
          'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
        )}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expiration card
// ---------------------------------------------------------------------------
function ExpirationCard({
  env,
  qc,
}: {
  env: string;
  qc: ReturnType<typeof useQueryClient>;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [pending, setPending] = useState<EnvExpirationAction | null>(null);

  const mutation = useMutation({
    mutationFn: (action: EnvExpirationAction) => patchEnvironmentExpiration(env, { action }),
    onMutate: (action) => setPending(action),
    onSettled: () => setPending(null),
    onSuccess: () => {
      setErr(null);
      void qc.invalidateQueries({ queryKey: ['environment', env] });
    },
    onError: (e) => {
      if (e instanceof AuthError) {
        window.location.href = '/login';
        return;
      }
      setErr(e instanceof Error ? e.message : 'Action failed');
    },
  });

  const actions: { value: EnvExpirationAction; label: string; description: string }[] = [
    { value: 'extend', label: 'Extend', description: 'Push the expiration out by the default window.' },
    { value: 'rotate', label: 'Rotate', description: 'Generate new enroll + remove secrets.' },
    { value: 'expire', label: 'Expire now', description: 'Immediately invalidate the enroll link.' },
    { value: 'not-expire', label: 'Never expire', description: 'Disable expiration entirely.' },
  ];

  return (
    <section className="border border-[color:var(--border)] rounded-md bg-[color:var(--bg-1)] p-4">
      <h2 className="font-display text-sm font-semibold text-[color:var(--text-1)] mb-2">
        Enrollment lifecycle
      </h2>
      <p className="text-[10px] text-[color:var(--text-3)] mb-3">
        Manage the enroll / remove link expiration for this environment.
      </p>
      <div className="grid grid-cols-2 gap-2">
        {actions.map((a) => (
          <button
            key={a.value}
            type="button"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate(a.value)}
            className={cn(
              'text-left px-3 py-2 rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)]',
              'hover:border-[color:var(--signal)] hover:bg-[color:var(--bg-3)] transition-colors',
              'disabled:opacity-50 disabled:cursor-not-allowed',
            )}
          >
            <div className="text-xs font-semibold text-[color:var(--text-1)] font-mono-tabular">
              {pending === a.value ? `${a.label}…` : a.label}
            </div>
            <div className="text-[10px] text-[color:var(--text-3)] mt-0.5">{a.description}</div>
          </button>
        ))}
      </div>
      {err && (
        <p
          role="alert"
          className="mt-3 text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-3 py-2 rounded-md"
        >
          {err}
        </p>
      )}
    </section>
  );
}

export default EnvConfigPage;
