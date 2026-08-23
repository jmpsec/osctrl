import { useState } from 'react';
import { AlertTriangle, Code2, MousePointer2 } from 'lucide-react';
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
import { NoCodeQueryBuilder, type QueryBuilderSummary } from './components/NoCodeQueryBuilder';
import { Button } from '$/components/atoms/Button';
import { cn } from '$/lib/cn';

const EMPTY_TARGET: TargetSelection = {
  uuids: [],
  platforms: [],
  tags: [],
  hosts: [],
};

function summarizeTarget(target: TargetSelection) {
  if (target.platforms.includes('all')) return 'All nodes';

  const parts: string[] = [];
  const directNodeCount = target.uuids.length + target.hosts.length;
  if (directNodeCount > 0) parts.push(`${directNodeCount} node${directNodeCount === 1 ? '' : 's'}`);
  if (target.platforms.length > 0) parts.push(target.platforms.join(' + '));
  if (target.tags.length > 0) parts.push(`${target.tags.length} tag${target.tags.length === 1 ? '' : 's'}`);
  return parts.length > 0 ? parts.join(' + ') : 'All nodes';
}

export function QueryRunPage() {
  usePageTitle('New Query');
  const { env } = useParams({ from: '/_app/env/$env/queries/new' });
  const navigate = useNavigate({ from: '/_app/env/$env/queries/new' });
  const search = useSearch({ from: '/_app/env/$env/queries/new' });
  const prefillSql = (search as { sql?: string }).sql;
  const prefillName = (search as { name?: string }).name;

  const [sql, setSql] = useState(prefillSql ?? 'SELECT * FROM osquery_info;');
  const [composerMode, setComposerMode] = useState<'builder' | 'sql'>(prefillSql ? 'sql' : 'builder');
  const [target, setTarget] = useState<TargetSelection>(EMPTY_TARGET);
  const [expHours, setExpHours] = useState<number>(24);
  const [hidden, setHidden] = useState(false);
  const [builderSummary, setBuilderSummary] = useState<QueryBuilderSummary>({
    columnLabel: 'All columns',
    filterCount: 0,
    limit: 100,
  });
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
  const targetSummary = summarizeTarget(target);
  const scopeSummary = composerMode === 'builder'
    ? `${builderSummary.columnLabel} · ${builderSummary.filterCount === 0 ? 'No filters' : `${builderSummary.filterCount} filter${builderSummary.filterCount === 1 ? '' : 's'}`} · ${targetSummary} · Limit ${builderSummary.limit}`
    : `Custom SQL · ${targetSummary}`;
  const isBroadQuery = composerMode === 'builder'
    && builderSummary.columnLabel === 'All columns'
    && builderSummary.filterCount === 0
    && targetSummary === 'All nodes';

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Page header ───────────────────────────────────────────────── */}
      <div className="px-6 py-4 border-b border-[color:var(--border)] flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[color:var(--text-3)] mb-0.5 select-none">
            queries · new
          </div>
          <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)]">
            Run distributed query
          </h1>
          <p className="text-xs text-[color:var(--text-2)] mt-0.5">
            {prefillName ? (
              <>
                Running saved query{' '}
                <span className="font-medium text-[color:var(--signal)]">{prefillName}</span>
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
              className="empty:hidden rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] p-4"
              aria-label="Query templates"
            >
              <QuickTemplates
                onPick={(s) => {
                  setSql(s.sql);
                  setComposerMode('sql');
                  setSubmitError(null);
                }}
              />
            </section>

            {/* Query composer */}
            <section
              className="rounded-xl border border-[color:var(--border)] bg-[color:var(--bg-1)] overflow-hidden"
              aria-label="Query composer"
            >
              <div className="flex min-h-12 flex-wrap items-center justify-between gap-3 border-b border-[color:var(--border)] px-4 py-2">
                <div>
                  <h2 id="sql-query-label" className="text-sm font-semibold text-[color:var(--text-1)]">
                    Query composer
                  </h2>
                  <p className="text-xs text-[color:var(--text-3)]">
                    {composerMode === 'builder' ? 'Build a SELECT query without writing SQL.' : 'Write or refine the SQL directly.'}
                  </p>
                </div>
                <div
                  role="tablist"
                  aria-label="Query composer mode"
                  className="flex max-w-full items-center gap-0.5 overflow-x-auto rounded-md border border-[color:var(--border)] bg-[color:var(--bg-2)] p-0.5"
                >
                  <button
                    type="button"
                    role="tab"
                    aria-selected={composerMode === 'builder'}
                    onClick={() => setComposerMode('builder')}
                    className={cn(
                      'inline-flex h-7 shrink-0 items-center gap-1.5 rounded px-2 text-xs text-[color:var(--text-2)]',
                      'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
                      composerMode === 'builder' && 'bg-[color:var(--bg-1)] text-[color:var(--text-1)]',
                    )}
                  >
                    <MousePointer2 size={14} strokeWidth={1.8} aria-hidden className="shrink-0" />
                    Builder
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={composerMode === 'sql'}
                    onClick={() => setComposerMode('sql')}
                    className={cn(
                      'inline-flex h-7 shrink-0 items-center gap-1.5 rounded px-2 text-xs text-[color:var(--text-2)]',
                      'focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[color:var(--signal)]',
                      composerMode === 'sql' && 'bg-[color:var(--bg-1)] text-[color:var(--text-1)]',
                    )}
                  >
                    <Code2 size={14} strokeWidth={1.8} aria-hidden className="shrink-0" />
                    SQL
                  </button>
                </div>
              </div>
              {composerMode === 'builder' ? (
                <NoCodeQueryBuilder
                  onSqlChange={setSql}
                  onEditSql={() => setComposerMode('sql')}
                  draftKey={`osctrl:query-builder:v1:${env}`}
                  onSummaryChange={setBuilderSummary}
                />
              ) : (
                <div>
                  <div className="flex items-center justify-end border-b border-[color:var(--border)] bg-[color:var(--bg-2)]/50 px-4 py-1.5 text-xs font-medium text-[color:var(--text-3)]">
                    osquery · SELECT only
                  </div>
                  <CodeEditor
                    value={sql}
                    onChange={setSql}
                    language="sql"
                    height="360px"
                    aria-labelledby="sql-query-label"
                  />
                </div>
              )}
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
          <div className="flex flex-col gap-1.5">
            <div
              aria-label={`Run scope: ${scopeSummary}`}
              className={cn(
                'flex min-w-0 items-start gap-1.5 text-sm sm:items-center',
                isBroadQuery ? 'text-[color:var(--warning)]' : 'text-[color:var(--text-3)]',
              )}
            >
              {isBroadQuery && <AlertTriangle size={16} strokeWidth={1.8} aria-hidden className="shrink-0" />}
              <span className="min-w-0 tabular-nums sm:truncate">{scopeSummary}</span>
            </div>
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
                  name="save-name"
                  aria-label="Saved query name"
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
                    'bg-[color:var(--bg-2)] text-[color:var(--text-1)] w-60',
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
                className="text-xs text-[color:var(--danger)] bg-[rgba(var(--danger-r),var(--danger-g),var(--danger-b),0.08)] px-2 py-0.5 rounded inline-block"
              >
                {saveError}
              </span>
            )}
            {saveOK && (
              <span
                role="status"
                className="text-xs text-[color:var(--success)] bg-[rgba(var(--success-r),var(--success-g),var(--success-b),0.08)] px-2 py-0.5 rounded inline-block"
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
