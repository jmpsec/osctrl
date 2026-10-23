import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2 } from 'lucide-react';
import {
  deleteOsqueryVersion,
  listOsqueryVersions,
  osqueryVersionsQueryKey,
  putOsqueryVersion,
} from '$/api/osqueryVersions';
import type { OsqueryEntryRequest } from '$/api/types';
import { usePageTitle } from '$/lib/usePageTitle';
import { buttonClasses } from '$/components/atoms/Button';
import { ModalShell } from '$/components/feedback/ModalShell';
import { EmptyState } from '$/components/data/EmptyState';

const IN_USE_TIP = 'Assigned to an environment or host';
const SHA256_RE = /^[0-9a-f]{64}$/;

// The platform/arch/format combinations the server accepts.
const PACKAGES: ReadonlyArray<{ platform: string; arch: string; format: string }> = [
  { platform: 'linux', arch: 'amd64', format: 'deb' },
  { platform: 'linux', arch: 'arm64', format: 'deb' },
  { platform: 'linux', arch: 'amd64', format: 'rpm' },
  { platform: 'linux', arch: 'arm64', format: 'rpm' },
  { platform: 'darwin', arch: 'universal', format: 'pkg' },
];
const pkgLabel = (p: { platform: string; arch: string; format: string }) => `${p.platform} / ${p.format} / ${p.arch}`;

const inputClass =
  'w-full h-8 px-2.5 text-sm rounded-md bg-[color:var(--bg-1)] text-[color:var(--text-1)] ' +
  'border border-[color:var(--border-strong)] outline-none focus:border-[color:var(--accent)]';
const labelClass = 'block text-xs font-semibold text-[color:var(--text-2)] mb-1';

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Super admin: the SHA-256 library of official osquery packages. */
export function OsqueryVersionsPage() {
  usePageTitle('Osquery versions');
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const { data, isLoading, error: loadError } = useQuery({
    queryKey: osqueryVersionsQueryKey,
    queryFn: listOsqueryVersions,
  });

  const remove = useMutation({
    mutationFn: (v: string) => deleteOsqueryVersion(v),
    onSuccess: () => {
      setError(null);
      setDeleting(null);
      void qc.invalidateQueries({ queryKey: osqueryVersionsQueryKey });
    },
    onError: (e) => {
      setDeleting(null);
      setError(errMsg(e));
    },
  });

  const rows = data ?? [];

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[color:var(--border)] flex-wrap">
        <h1 className="font-display text-lg font-semibold text-[color:var(--text-1)] mr-2">Osquery versions</h1>
        <p className="text-xs text-[color:var(--text-3)] flex-1">
          SHA-256 of the official osquery packages osctrld may install. An upgrade never runs without a digest.
        </p>
        <button type="button" className={buttonClasses({ size: 'md' })} onClick={() => setAdding(true)}>
          <Plus size={14} /> Add version
        </button>
      </div>

      {(error || loadError) && (
        <div
          role="alert"
          className="mx-4 mt-3 px-3 py-2 text-sm rounded-md border border-[color:var(--danger)]/30 bg-[color:var(--danger)]/10 text-[color:var(--danger)]"
        >
          {error ?? errMsg(loadError)}
        </div>
      )}

      <div className="flex-1 overflow-auto min-h-0 p-4 space-y-4">
        {isLoading ? (
          <p className="text-sm text-[color:var(--text-3)]">Loading versions…</p>
        ) : rows.length === 0 ? (
          <EmptyState title="No osquery versions" description="Add a version with the SHA-256 of its packages." />
        ) : (
          rows.map((v) => (
            <section key={v.version} className="border border-[color:var(--border)] rounded-md">
              <header className="flex items-center gap-3 px-3 py-2 border-b border-[color:var(--border)]">
                <h2 className="font-medium text-[color:var(--text-1)]">{v.version}</h2>
                {v.in_use && <span className="text-xs text-[color:var(--text-3)]">in use</span>}
                <button
                  type="button"
                  aria-label={`Delete ${v.version}`}
                  title={v.in_use ? IN_USE_TIP : undefined}
                  disabled={v.in_use}
                  onClick={() => setDeleting(v.version)}
                  className={buttonClasses({ variant: 'danger', size: 'sm', className: 'ml-auto' })}
                >
                  <Trash2 size={13} /> Delete
                </button>
              </header>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-[color:var(--text-3)]">
                    <th className="px-3 py-1 font-medium">Platform</th>
                    <th className="px-3 py-1 font-medium">Arch</th>
                    <th className="px-3 py-1 font-medium">Format</th>
                    <th className="px-3 py-1 font-medium">SHA-256</th>
                    <th className="px-3 py-1 font-medium">Created by</th>
                  </tr>
                </thead>
                <tbody>
                  {v.entries.map((e) => (
                    <tr key={`${e.platform}/${e.arch}/${e.format}`} className="border-t border-[color:var(--border)]">
                      <td className="px-3 py-1">{e.platform}</td>
                      <td className="px-3 py-1">{e.arch}</td>
                      <td className="px-3 py-1">{e.format}</td>
                      <td className="px-3 py-1 font-mono text-xs break-all">{e.sha256}</td>
                      <td className="px-3 py-1">{e.created_by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ))
        )}
      </div>

      {adding && (
        <AddVersionDialog
          onClose={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            setError(null);
            void qc.invalidateQueries({ queryKey: osqueryVersionsQueryKey });
          }}
        />
      )}

      {deleting && (
        <ModalShell
          title={`Delete osquery ${deleting}?`}
          titleId="osquery-version-delete-title"
          onClose={() => setDeleting(null)}
          panelClassName="max-w-md"
        >
          <div className="space-y-4">
            <p className="text-sm text-[color:var(--text-1)]">
              The digests of this version are removed from the library.
            </p>
            <div className="flex justify-end gap-2">
              <button type="button" className={buttonClasses({ variant: 'ghost' })} onClick={() => setDeleting(null)}>
                Cancel
              </button>
              <button
                type="button"
                className={buttonClasses({ variant: 'danger' })}
                disabled={remove.isPending}
                onClick={() => remove.mutate(deleting)}
              >
                Confirm delete
              </button>
            </div>
          </div>
        </ModalShell>
      )}
    </div>
  );
}

type Row = { pkg: number; sha: string };

/** Adding an existing version replaces the digests of the packages entered. */
function AddVersionDialog({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [version, setVersion] = useState('');
  const [rows, setRows] = useState<Row[]>([{ pkg: 0, sha: '' }]);
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (entries: OsqueryEntryRequest[]) => putOsqueryVersion(version.trim(), entries),
    onSuccess: onSaved,
    onError: (e) => setError(errMsg(e)),
  });

  const patch = (i: number, p: Partial<Row>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...p } : r)));

  function submit(e: FormEvent) {
    e.preventDefault();
    if (rows.some((r) => !SHA256_RE.test(r.sha))) {
      setError('Each SHA-256 must be 64 lowercase hex characters.');
      return;
    }
    setError(null);
    save.mutate(rows.map((r) => ({ ...PACKAGES[r.pkg], sha256: r.sha })));
  }

  return (
    <ModalShell title="Add osquery version" titleId="osquery-version-add-title" onClose={onClose} panelClassName="max-w-2xl">
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="osq-version" className={labelClass}>Version</label>
          <input id="osq-version" className={inputClass} value={version} required placeholder="5.13.0" onChange={(e) => setVersion(e.target.value)} />
        </div>
        {rows.map((r, i) => (
          <div key={i} className="grid grid-cols-[12rem_1fr_auto] gap-2 items-end">
            <div>
              <label htmlFor={`osq-pkg-${i}`} className={labelClass}>{`Package ${i + 1}`}</label>
              <select id={`osq-pkg-${i}`} className={inputClass} value={r.pkg} onChange={(e) => patch(i, { pkg: Number(e.target.value) })}>
                {PACKAGES.map((p, k) => (
                  <option key={k} value={k}>{pkgLabel(p)}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor={`osq-sha-${i}`} className={labelClass}>{`SHA-256 ${i + 1}`}</label>
              <input
                id={`osq-sha-${i}`}
                className={`${inputClass} font-mono`}
                value={r.sha}
                spellCheck={false}
                autoComplete="off"
                onChange={(e) => patch(i, { sha: e.target.value.trim() })}
              />
            </div>
            <button
              type="button"
              aria-label={`Remove package ${i + 1}`}
              disabled={rows.length === 1}
              className={buttonClasses({ variant: 'ghost', size: 'sm' })}
              onClick={() => setRows(rows.filter((_, j) => j !== i))}
            >
              <Trash2 size={13} />
            </button>
          </div>
        ))}
        <button type="button" className={buttonClasses({ variant: 'ghost', size: 'sm' })} onClick={() => setRows([...rows, { pkg: 0, sha: '' }])}>
          <Plus size={13} /> Add package
        </button>
        {error && (
          <p role="alert" className="text-sm text-[color:var(--danger)]">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <button type="button" className={buttonClasses({ variant: 'ghost' })} onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className={buttonClasses()} disabled={save.isPending}>
            Save version
          </button>
        </div>
      </form>
    </ModalShell>
  );
}
