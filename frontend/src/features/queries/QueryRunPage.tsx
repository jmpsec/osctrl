import { useState } from 'react';
import { usePageTitle } from '$/lib/usePageTitle';
import { useParams, useNavigate, useSearch } from '@tanstack/react-router';
import { runQuery } from '$/api/queries';
import { createSavedQuery } from '$/api/saved-queries';
import { AuthError, ApiError } from '$/api/client';
import { CodeEditor } from '$/components/forms/CodeEditor';
import type { TargetSelection } from '$/components/forms/TargetSelector';
import { QuickTemplates } from './components/QuickTemplates';
import { TargetingPanel } from './components/TargetingPanel';
import { OptionsPanel } from './components/OptionsPanel';
import { StickyFooter } from './components/StickyFooter';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';

const EMPTY_TARGET: TargetSelection = {
  uuids: [],
  platforms: [],
  tags: [],
  hosts: [],
};

export function QueryRunPage() {
  usePageTitle('New Query');
  const { env } = useParams({ from: '/_app/env/$env/queries/new' });
  const navigate = useNavigate({ from: '/_app/env/$env/queries/new' });
  const search = useSearch({ from: '/_app/env/$env/queries/new' });
  const prefillSql = (search as { sql?: string }).sql;
  const prefillName = (search as { name?: string }).name;

  const [sql, setSql] = useState(prefillSql ?? 'SELECT * FROM osquery_info;');
  const [target, setTarget] = useState<TargetSelection>(EMPTY_TARGET);
  const [expHours, setExpHours] = useState<number>(24);
  const [hidden, setHidden] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // "Save as…" inline form state.
  const [saveName, setSaveName] = useState('');
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveOK, setSaveOK] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  async function handleSave() {
    const trimmedName = saveName.trim();
    if (!trimmedName) {
      setSaveError('Name is required.');
      return;
    }
    if (!sql.trim()) {
      setSaveError('Query SQL cannot be empty.');
      return;
    }
    setIsSaving(true);
    setSaveError(null);
    setSaveOK(null);
    try {
      await createSavedQuery(env, { name: trimmedName, query: sql });
      setSaveOK(`Saved as "${trimmedName}"`);
      setSaveName('');
    } catch (err) {
      if (err instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      if (err instanceof ApiError && err.status === 409) {
        setSaveError('A saved query with that name already exists.');
      } else {
        setSaveError(err instanceof Error ? err.message : 'Save failed');
      }
    } finally {
      setIsSaving(false);
    }
  }

  async function handleSubmit() {
    if (!sql.trim()) {
      setSubmitError('Query SQL cannot be empty.');
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const result = await runQuery(env, {
        query: sql,
        uuid_list: target.uuids.length > 0 ? target.uuids : undefined,
        platform_list: target.platforms.length > 0 ? target.platforms : undefined,
        host_list: target.hosts.length > 0 ? target.hosts : undefined,
        tag_list: target.tags.length > 0 ? target.tags : undefined,
        hidden,
        exp_hours: expHours,
      });
      void navigate({
        to: '/_app/env/$env/queries/$name',
        params: { env, name: result.query_name },
      });
    } catch (err) {
      if (err instanceof AuthError) {
        void navigate({ to: '/login' });
        return;
      }
      setSubmitError(err instanceof Error ? err.message : 'Failed to run query');
      setIsSubmitting(false);
    }
  }

  const footerMessage = submitError
    ? ({ tone: 'error', text: submitError } as const)
    : null;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Page header ───────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)] flex items-start justify-between gap-4">
        <div>
          <div className="text-[10px] font-mono-tabular uppercase tracking-[0.14em] text-[color:var(--text-3)] mb-0.5 select-none">
            queries · new
          </div>
          <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
            Run distributed query
          </h1>
          <p className="text-xs text-[color:var(--text-2)] mt-0.5">
            {prefillName ? (
              <>
                Running saved query{' '}
                <span className="font-mono-tabular text-[color:var(--signal)]">{prefillName}</span>
                {' '}— review the SQL and targets before dispatching.
              </>
            ) : (
              <>Dispatches to matching nodes on next check-in.</>
            )}
          </p>
        </div>
      </div>

      {/* ── Scroll container ──────────────────────────────────────────── */}
      <div className="flex-1 min-h-0 overflow-auto">
        <div
          className={cn(
            'grid gap-6 p-6',
            // 1-col on small/medium, 3-col grid on lg: editor 2/3, targeting 1/3.
            'lg:grid-cols-3 max-w-[1400px] mx-auto',
          )}
        >
          {/* ── Left: editor + templates ─────────────────────────────── */}
          <div className="lg:col-span-2 space-y-4">
            {/* Quick templates */}
            <section
              className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
              aria-label="Query templates"
            >
              <QuickTemplates
                onPick={(s) => {
                  setSql(s.sql);
                  setSubmitError(null);
                }}
              />
            </section>

            {/* Editor */}
            <section
              className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
              aria-label="SQL editor"
            >
              <div className="flex items-center justify-between px-4 h-10 border-b border-[color:var(--border)]">
                <div className="flex items-center gap-2">
                  <span
                    aria-hidden
                    className="w-1.5 h-1.5 rounded-full bg-[color:var(--signal)]"
                  />
                  <span
                    id="sql-query-label"
                    className="text-[12px] font-medium text-[color:var(--text-1)]"
                  >
                    SQL query
                  </span>
                </div>
                <div className="text-[10px] font-mono-tabular text-[color:var(--text-3)] uppercase tracking-[0.12em]">
                  osquery · SELECT only
                </div>
              </div>
              <CodeEditor
                value={sql}
                onChange={setSql}
                language="sql"
                height="320px"
                aria-labelledby="sql-query-label"
              />
            </section>

            {/* Options */}
            <section
              className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
              aria-label="Options"
            >
              <OptionsPanel
                expHours={expHours}
                onExpChange={setExpHours}
                hidden={hidden}
                onHiddenChange={setHidden}
              />
            </section>
          </div>

          {/* ── Right: targeting + save-as ──────────────────────────── */}
          <aside
            aria-label="Targeting"
            className="lg:col-span-1 space-y-4 lg:sticky lg:top-4 lg:self-start"
          >
            <section className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4">
              <h2 className="text-[12px] font-display font-semibold text-[color:var(--text-1)] mb-3">
                Target
              </h2>
              <TargetingPanel value={target} onChange={setTarget} env={env} />
            </section>
          </aside>
        </div>
      </div>

      {/* ── Sticky footer ────────────────────────────────────────────── */}
      <StickyFooter
        submitting={isSubmitting}
        disabled={isSubmitting}
        message={footerMessage}
        onSubmit={() => void handleSubmit()}
        onCancel={() => void navigate({ to: '/_app/env/$env/queries', params: { env } })}
        submitLabel="Run query"
        middle={
          <div className="flex flex-col gap-1">
            {!saveOpen ? (
              <button
                type="button"
                onClick={() => setSaveOpen(true)}
                className={cn(
                  'self-start text-xs text-[color:var(--text-link)] hover:underline',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:outline-[color:var(--signal)] rounded',
                )}
              >
                Save as…
              </button>
            ) : (
              <div className="flex items-center gap-2 flex-wrap">
                <input
                  id="save-name"
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  onKeyDown={(e) => {
                    // Intercept Enter to save (footer is outside <form>; this is here only for parity).
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      void handleSave();
                    } else if (e.key === 'Escape') {
                      e.preventDefault();
                      setSaveOpen(false);
                      setSaveName('');
                      setSaveError(null);
                      setSaveOK(null);
                    }
                  }}
                  placeholder="Name for the saved query"
                  className={cn(
                    'px-2 py-1 text-xs rounded border border-[color:var(--border)]',
                    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] font-mono-tabular w-60',
                    'focus:outline focus:outline-2 focus:outline-[color:var(--signal)]',
                  )}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => void handleSave()}
                  disabled={isSaving}
                >
                  {isSaving ? 'Saving…' : 'Save'}
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    setSaveOpen(false);
                    setSaveName('');
                    setSaveError(null);
                    setSaveOK(null);
                  }}
                  className="px-2 py-1 text-xs text-[color:var(--text-3)] hover:text-[color:var(--text-1)] rounded"
                >
                  Cancel
                </button>
              </div>
            )}
            {saveError && (
              <span
                role="alert"
                className="text-[10px] text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-2 py-0.5 rounded inline-block"
              >
                {saveError}
              </span>
            )}
            {saveOK && (
              <span
                role="status"
                className="text-[10px] text-[color:var(--success)] bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)] px-2 py-0.5 rounded inline-block"
              >
                {saveOK}
              </span>
            )}
          </div>
        }
      />
    </div>
  );
}

export default QueryRunPage;
