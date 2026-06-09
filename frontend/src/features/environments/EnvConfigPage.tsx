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

  // Page is tabbed: 'settings' (intervals + expiration) plus one tab per
  // config SECTION. The "settings" default keeps the slider-based forms
  // up-front so an operator who lands here to tune pull intervals doesn't
  // scroll past six 280px Monaco editors first.
  type TabKey = 'settings' | SectionKey;
  const [activeTab, setActiveTab] = useState<TabKey>('settings');

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

      {/* ── Tab bar ──
          Settings tab first (slider-based, no Monaco) so the page loads
          cheap on first view. Each section tab carries its dirty-state
          dot so operators can see at a glance which sections have
          pending edits without clicking through every tab. */}
      <div
        role="tablist"
        aria-label="Configuration sections"
        className="flex items-center gap-1 px-2 border-b border-[color:var(--border)] overflow-x-auto"
      >
        <TabButton
          id="settings"
          label="Settings"
          active={activeTab === 'settings'}
          onClick={() => setActiveTab('settings')}
        />
        {SECTIONS.map(({ key, label }) => (
          <TabButton
            key={key}
            id={key}
            label={label}
            active={activeTab === key}
            dirty={dirty.has(key)}
            onClick={() => setActiveTab(key)}
          />
        ))}
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
        {activeTab === 'settings' && (
          <>
            {envInfo && (
              <IntervalsCard env={env} envInfo={envInfo} qc={qc} />
            )}
            {envInfo && (
              <ExpirationCard env={env} qc={qc} />
            )}
          </>
        )}

        {SECTIONS.map(({ key, label, language, help }) => {
          if (activeTab !== key) return null;
          const isDirty = dirty.has(key);
          const before = cfgQuery.data?.[key] ?? '';
          const after = draft[key];
          return (
            <section
              key={key}
              className="border border-[color:var(--border)] rounded-md overflow-hidden bg-[color:var(--bg-1)]"
              role="tabpanel"
              aria-labelledby={`tab-${key}`}
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
                height="420px"
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
// TabButton — underline tab matching the rest of the SPA. Renders a small
// dot to the right of the label when `dirty` so unsaved edits in non-active
// sections are visible without switching tabs.
// ---------------------------------------------------------------------------
function TabButton({
  id,
  label,
  active,
  dirty,
  onClick,
}: {
  id: string;
  label: string;
  active: boolean;
  dirty?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      id={`tab-${id}`}
      aria-selected={active}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 px-3 pt-2 pb-1.5 text-xs whitespace-nowrap',
        'border-b-2 transition-colors',
        'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        active
          ? 'border-[color:var(--signal)] text-[color:var(--text-1)] font-semibold'
          : 'border-transparent text-[color:var(--text-3)] hover:text-[color:var(--text-1)]',
      )}
    >
      {label}
      {dirty && (
        <span
          aria-hidden
          className="w-1.5 h-1.5 rounded-full bg-[color:var(--warning)]"
          title="Unsaved changes"
        />
      )}
    </button>
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
      {/* Ranges match the legacy admin's conf.html sliders exactly:
            Configuration  10–600, step 10
            Logging        10–600, step 10
            Query          10–300, step 1
          Same min/max/step keeps fleets that were tuned on legacy
          render identically here. */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <IntervalField
          id="iv-cfg"
          label="Configuration Interval"
          value={cfg}
          onChange={setCfg}
          min={10}
          max={600}
          step={10}
        />
        <IntervalField
          id="iv-log"
          label="Logging Interval"
          value={lg}
          onChange={setLg}
          min={10}
          max={600}
          step={10}
        />
        <IntervalField
          id="iv-qry"
          label="Query Interval"
          value={qr}
          onChange={setQr}
          min={10}
          max={300}
          step={1}
        />
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

/**
 * IntervalField — range slider with live numeric readout, mirroring the
 * legacy admin's conf.html intervals form. min/max/step come from the
 * caller so different fields can have different ranges (the legacy
 * template has Query as 10–300 step 1 while Config/Logging are 10–600
 * step 10). Bounds are also enforced when typing into the number input
 * so the slider and the number stay in sync.
 */
function IntervalField({
  id,
  label,
  value,
  onChange,
  min,
  max,
  step,
}: {
  id: string;
  label: string;
  value: number;
  onChange: (v: number) => void;
  min: number;
  max: number;
  step: number;
}) {
  function clamp(v: number) {
    if (Number.isNaN(v)) return value;
    return Math.min(max, Math.max(min, v));
  }
  return (
    <div>
      <label
        htmlFor={id}
        className="block text-xs font-medium text-[color:var(--text-2)] mb-1.5"
      >
        {label}:{' '}
        <span className="font-mono-tabular font-semibold text-[color:var(--text-1)] tabular-nums">
          {value}
        </span>{' '}
        <span className="text-[color:var(--text-3)]">seconds</span>
      </label>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(clamp(Number(e.target.value)))}
        className={cn(
          'w-full accent-[color:var(--signal)] cursor-pointer',
          'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)]',
        )}
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={value}
      />
      <div className="flex items-center justify-between mt-1 text-[10px] font-mono-tabular text-[color:var(--text-3)] tabular-nums">
        <span>{min}</span>
        <input
          type="number"
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(e) => onChange(clamp(Number(e.target.value)))}
          className={cn(
            'w-16 px-1.5 py-0.5 text-[10px] rounded',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)]',
            'text-[color:var(--text-1)] font-mono-tabular text-center tabular-nums',
            'focus:outline focus:outline-1 focus:outline-[color:var(--signal)]',
          )}
          aria-label={`${label} numeric value`}
        />
        <span>{max}</span>
      </div>
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
