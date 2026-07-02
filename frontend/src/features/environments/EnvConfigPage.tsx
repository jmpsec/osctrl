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
import { DocsLink } from '$/components/atoms/DocsLink';
import { AssembledConfigCard } from '$/features/enrollment/AssembledConfigCard';

type SectionKey = 'options' | 'schedule' | 'packs' | 'decorators' | 'atc' | 'flags';

// docs URLs point at the upstream osquery read-the-docs anchors so an
// operator can jump from the section header straight to the canonical
// reference for that part of the config. `latest` is intentional — pinning
// to a version would drift as osquery releases.
const SECTIONS: {
  key: SectionKey;
  label: string;
  language: string;
  help: string;
  docsUrl: string;
}[] = [
  {
    key: 'options',
    label: 'Options',
    language: 'json',
    help: 'Top-level osquery `options` block.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/installation/cli-flags/#configuration-control-flags',
  },
  {
    key: 'schedule',
    label: 'Schedule',
    language: 'json',
    help: 'Scheduled query map keyed by name.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/deployment/configuration/#schedule',
  },
  {
    key: 'packs',
    label: 'Packs',
    language: 'json',
    help: 'Named query packs delivered with the config.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/deployment/configuration/#query-packs',
  },
  {
    key: 'decorators',
    label: 'Decorators',
    language: 'json',
    help: 'Decorator queries that prefix every result.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/deployment/configuration/#decorator-queries',
  },
  {
    key: 'atc',
    label: 'ATC',
    language: 'json',
    help: 'Auto Table Construction — third-party SQLite virtual tables.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/deployment/configuration/#automatic-table-construction',
  },
  {
    key: 'flags',
    label: 'Flags',
    language: 'plaintext',
    help: 'CLI flags appended to osquery on startup.',
    docsUrl: 'https://osquery.readthedocs.io/en/latest/installation/cli-flags/',
  },
];

// Names that JavaScript treats specially on an object literal. Assigning
// to `__proto__` mutates the prototype chain instead of creating an own
// property, so the surrounding JSON.stringify silently drops the entry —
// confusing UX, and a real prototype-pollution bug waiting to happen if
// someone copies the AddOptionForm / AddScheduledQueryForm pattern into a
// path that reads off `parsed` later. Rejected up front by both inline
// forms below.
const RESERVED_OPTION_NAMES = new Set(['__proto__', 'constructor', 'prototype']);

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

  // Page is tabbed: 'settings' (intervals + expiration), one tab per
  // config SECTION. The "settings" default keeps the slider-based forms
  // up-front so an operator who lands here to tune pull intervals doesn't
  // scroll past six 280px Monaco editors first.
  type TabKey = 'settings' | SectionKey | 'assembled';
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
        <TabButton
          id="assembled"
          label="Full Configuration"
          active={activeTab === 'assembled'}
          onClick={() => {
            if (activeTab === 'assembled') {
              void qc.invalidateQueries({ queryKey: ['env', env, 'assembled-config'] });
            }
            setActiveTab('assembled');
          }}
        />
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

        {activeTab === 'assembled' && (
          <AssembledConfigCard env={env} />
        )}

        {SECTIONS.map(({ key, label, language, help, docsUrl }) => {
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
                <DocsLink href={docsUrl} label={`${label.toLowerCase()} docs`} />
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

              {/* Per-section inline form: Options + Schedule get the
                  legacy admin's add-row affordance so operators don't
                  have to know JSON to append a new entry. The forms
                  parse the current draft, mutate the parsed object,
                  re-serialize, and stuff it back into the draft state —
                  same path Save section already validates. */}
              {key === 'options' && (
                <AddOptionForm
                  draftValue={after}
                  onAdd={(next) =>
                    setDraft((d) => (d ? { ...d, options: next } : d))
                  }
                />
              )}
              {key === 'schedule' && (
                <AddScheduledQueryForm
                  draftValue={after}
                  onAdd={(next) =>
                    setDraft((d) => (d ? { ...d, schedule: next } : d))
                  }
                />
              )}

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

// ---------------------------------------------------------------------------
// AddOptionForm — inline form for the Options section. Lets operators
// append an option flag (key + typed value) without hand-editing JSON.
//
// On Add: parse the current draft as a JSON object, assign the new
// key with the typed value, re-serialize with 2-space indent so the
// CodeEditor's formatter doesn't re-pivot the whole document, and
// push the result back via onAdd. If the draft doesn't parse cleanly
// we error inline — the operator can fix the JSON manually first,
// then re-use the form.
// ---------------------------------------------------------------------------
function AddOptionForm({
  draftValue,
  onAdd,
}: {
  draftValue: string;
  onAdd: (next: string) => void;
}) {
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [type, setType] = useState<'string' | 'integer' | 'boolean'>('string');
  const [err, setErr] = useState<string | null>(null);

  function handleAdd() {
    setErr(null);
    const trimmedName = name.trim();
    if (!trimmedName) {
      setErr('Option name is required.');
      return;
    }
    if (RESERVED_OPTION_NAMES.has(trimmedName)) {
      setErr(`"${trimmedName}" is a reserved JavaScript property name and can't be used as an option key.`);
      return;
    }
    let parsed: Record<string, unknown>;
    try {
      const obj = JSON.parse(draftValue || '{}') as unknown;
      if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
        setErr('Options section is not a JSON object — fix it manually first.');
        return;
      }
      parsed = obj as Record<string, unknown>;
    } catch {
      setErr('Options section has invalid JSON — fix it manually first.');
      return;
    }
    let coerced: unknown = value;
    if (type === 'integer') {
      const n = Number(value);
      if (!Number.isFinite(n)) {
        setErr('Integer value must be a number.');
        return;
      }
      coerced = n;
    } else if (type === 'boolean') {
      if (value !== 'true' && value !== 'false') {
        setErr('Boolean value must be "true" or "false".');
        return;
      }
      coerced = value === 'true';
    }
    parsed[trimmedName] = coerced;
    onAdd(JSON.stringify(parsed, null, 2));
    setName('');
    setValue('');
  }

  return (
    <div className="px-3 py-2 border-b border-[color:var(--border)] bg-[color:var(--bg-1)]">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mr-1">
          Add option
        </span>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="option_name"
          className={cn(
            'flex-1 min-w-[120px] px-2 py-1 rounded text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value as typeof type)}
          className={cn(
            'px-2 py-1 rounded text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-2)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
          aria-label="Option value type"
        >
          <option value="string">string</option>
          <option value="integer">integer</option>
          <option value="boolean">boolean</option>
        </select>
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={type === 'boolean' ? 'true | false' : type === 'integer' ? '0' : 'value'}
          className={cn(
            'flex-1 min-w-[120px] px-2 py-1 rounded text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        <button
          type="button"
          onClick={handleAdd}
          className={cn(
            'text-xs px-3 py-1 rounded font-medium',
            'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
            'transition-colors',
          )}
        >
          Add
        </button>
      </div>
      {err && (
        <p role="alert" className="mt-1.5 text-[11px] text-[color:var(--danger)]">
          {err}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AddScheduledQueryForm — inline form for the Schedule section.
//
// Same shape as AddOptionForm but the value is an object
//   { "name": { "query": "<SQL>", "interval": <int> } }
// per osquery's schedule format. interval defaults to 60s, matching
// what the legacy admin's add-row affordance seeded the field with.
// ---------------------------------------------------------------------------
function AddScheduledQueryForm({
  draftValue,
  onAdd,
}: {
  draftValue: string;
  onAdd: (next: string) => void;
}) {
  const [name, setName] = useState('');
  const [query, setQuery] = useState('');
  const [interval, setInterval] = useState(60);
  const [err, setErr] = useState<string | null>(null);

  function handleAdd() {
    setErr(null);
    const trimmedName = name.trim();
    const trimmedQuery = query.trim();
    if (!trimmedName) {
      setErr('Query name is required.');
      return;
    }
    if (!trimmedQuery) {
      setErr('Query SQL is required.');
      return;
    }
    if (!Number.isFinite(interval) || interval < 1) {
      setErr('Interval must be a positive integer (seconds).');
      return;
    }
    if (RESERVED_OPTION_NAMES.has(trimmedName)) {
      setErr(`"${trimmedName}" is a reserved JavaScript property name and can't be used as a query name.`);
      return;
    }
    let parsed: Record<string, unknown>;
    try {
      const obj = JSON.parse(draftValue || '{}') as unknown;
      if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
        setErr('Schedule section is not a JSON object — fix it manually first.');
        return;
      }
      parsed = obj as Record<string, unknown>;
    } catch {
      setErr('Schedule section has invalid JSON — fix it manually first.');
      return;
    }
    if (Object.prototype.hasOwnProperty.call(parsed, trimmedName)) {
      setErr(`A query named "${trimmedName}" already exists in the schedule.`);
      return;
    }
    parsed[trimmedName] = { query: trimmedQuery, interval };
    onAdd(JSON.stringify(parsed, null, 2));
    setName('');
    setQuery('');
    setInterval(60);
  }

  return (
    <div className="px-3 py-2 border-b border-[color:var(--border)] bg-[color:var(--bg-1)] space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)]">
          Add scheduled query
        </span>
      </div>
      <div className="flex items-start gap-2 flex-wrap">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="query_name"
          className={cn(
            'w-[180px] px-2 py-1 rounded text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="SELECT … FROM osquery_info;"
          className={cn(
            'flex-1 min-w-[220px] px-2 py-1 rounded text-xs font-mono-tabular',
            'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
            'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
          )}
        />
        <label className="flex items-center gap-1 text-[10px] font-mono-tabular text-[color:var(--text-3)]">
          interval
          <input
            type="number"
            min={1}
            value={interval}
            onChange={(e) => setInterval(Number(e.target.value))}
            className={cn(
              'w-16 px-2 py-1 rounded text-xs font-mono-tabular text-center tabular-nums',
              'bg-[color:var(--bg-2)] border border-[color:var(--border)] text-[color:var(--text-1)]',
              'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
            )}
          />
          s
        </label>
        <button
          type="button"
          onClick={handleAdd}
          className={cn(
            'text-xs px-3 py-1 rounded font-medium',
            'bg-[color:var(--signal)] text-black hover:bg-[color:var(--signal-bright)]',
            'transition-colors',
          )}
        >
          Add
        </button>
      </div>
      {err && (
        <p role="alert" className="text-[11px] text-[color:var(--danger)]">
          {err}
        </p>
      )}
    </div>
  );
}

export default EnvConfigPage;
